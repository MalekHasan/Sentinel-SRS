// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.icu.text.ListFormatter
import android.text.format.DateUtils
import android.text.format.Formatter
import android.util.Log
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
import androidx.compose.ui.platform.LocalUriHandler
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
import io.github.malekhasan.sentinel.core.RemoteAccessService
import io.github.malekhasan.sentinel.core.SensorKind
import io.github.malekhasan.sentinel.core.SharingSiteKind
import io.github.malekhasan.sentinel.core.SpecialAccess
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
        Text(alertTitle(alert), style = MaterialTheme.typography.headlineSmall, modifier = Modifier.asHeading())
        Text(alertExplanation(alert), style = MaterialTheme.typography.bodyLarge)
        Text(raisedWhen(alert), style = MaterialTheme.typography.bodySmall)

        // An alert about Sentinel itself may have nothing more to show.
        if (alert.evidence.isNotEmpty()) {
            Text(
                stringResource(R.string.alert_evidence_title),
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.asHeading(),
            )
        }
        alert.evidence.forEach { evidence ->
            Text(describeEvidence(evidence, label), style = MaterialTheme.typography.bodyMedium)
        }
        if (alert.rule == AlertRule.KNOWN_INDICATOR) Advice()

        if (alert.actions.isNotEmpty()) {
            Text(
                stringResource(R.string.alert_actions_title),
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.asHeading(),
            )
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

/** MS-13: where to get help with a match. Each is also written out, to type on another device. */
val HELPLINES = listOf(
    R.string.alert_advice_access_now to "https://www.accessnow.org/help/",
    R.string.alert_advice_amnesty to "https://securitylab.amnesty.org/get-help/",
)

/**
 * MS-13, on every known-indicator alert: keep the evidence, move sensitive talk to
 * another device, and ask a helpline.
 */
@Composable
private fun Advice() {
    val links = LocalUriHandler.current
    Text(
        stringResource(R.string.alert_advice_title),
        style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.asHeading(),
    )
    Text(stringResource(R.string.alert_advice_keep), style = MaterialTheme.typography.bodyMedium)
    Text(stringResource(R.string.alert_advice_move), style = MaterialTheme.typography.bodyMedium)
    Text(stringResource(R.string.alert_advice_help), style = MaterialTheme.typography.bodyMedium)
    HELPLINES.forEach { (name, link) ->
        OutlinedButton(onClick = {
            try {
                links.openUri(link)
            } catch (e: RuntimeException) {
                // No browser: the address below can be typed elsewhere. Nothing is logged:
                // the log, or the exception's text, would say the user sought help, and
                // what can read the log may be what the user seeks help from (audit A-52).
            }
        }) { Text(stringResource(name)) }
        Text(isolate(link), style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * What the user thinks of the alert (AL-05): not useful, or fine to allow from now on,
 * and how to take it back. Only an alert about an app, and not a Critical one, can be
 * allowed: the core says which (ADR-0012, audit A-08).
 */
@Composable
private fun Feedback(alert: HistoryAlert, onFeedback: (AlertFeedback?) -> Unit) {
    Text(
        stringResource(R.string.alert_feedback_title),
        style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.asHeading(),
    )
    when (alert.feedback) {
        null -> {
            OutlinedButton(onClick = { onFeedback(AlertFeedback.NOT_USEFUL) }) {
                Text(stringResource(R.string.alert_feedback_not_useful))
            }
            if (alert.canAllow) {
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
            .opens(stringResource(R.string.a11y_open_alert)) { onOpen(alert.id) },
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

/** Whether the alert was found in the history after the fact (MS-02). */
private fun HistoryAlert.past(): Boolean = evidence.any { it is AlertEvidence.PastConnections }

/** Whether the alert is about an installed app the indicator list names (ID-13). */
private fun HistoryAlert.installedApp(): Boolean = evidence.any {
    it is AlertEvidence.Indicator &&
        (it.sighting == IndicatorSighting.INSTALLED_PACKAGE || it.sighting == IndicatorSighting.SIGNING_CERTIFICATE)
}

/** The sensor the alert is about, if any (SE-04). */
private fun HistoryAlert.sensor(): SensorKind? =
    evidence.firstNotNullOfOrNull { (it as? AlertEvidence.Sensor)?.sensor }

/** The special access the alert is about, if any (ID-12). */
private fun HistoryAlert.access(): SpecialAccess? =
    evidence.firstNotNullOfOrNull { (it as? AlertEvidence.Access)?.access }

/**
 * The alert's title: its rule's, a blocked new app's, an installed app's, a match found
 * in the history, or the kind of special access an app gained.
 */
fun titleRes(alert: HistoryAlert): Int = when {
    alert.rule == AlertRule.FIRST_NETWORK_USE && alert.blocked() -> R.string.alert_first_network_use_blocked_title
    alert.rule == AlertRule.KNOWN_INDICATOR && alert.installedApp() -> R.string.alert_known_indicator_app_title
    alert.rule == AlertRule.KNOWN_INDICATOR && alert.past() -> R.string.alert_known_indicator_past_title
    alert.rule == AlertRule.SPECIAL_ACCESS -> alert.access()?.let { titleRes(it) } ?: titleRes(alert.rule)
    alert.rule == AlertRule.SENSOR_WHILE_AWAY -> when (alert.sensor()) {
        SensorKind.MICROPHONE -> R.string.alert_microphone_while_away_title
        SensorKind.CAMERA -> R.string.alert_camera_while_away_title
        null -> titleRes(alert.rule)
    }
    else -> titleRes(alert.rule)
}

/** The title of an alert about an app that gained [access] (ID-12). */
fun titleRes(access: SpecialAccess): Int = when (access) {
    SpecialAccess.ACCESSIBILITY -> R.string.alert_accessibility_title
    SpecialAccess.DEVICE_ADMIN -> R.string.alert_device_admin_title
    SpecialAccess.NOTIFICATION_LISTENER -> R.string.alert_notification_access_title
}

/**
 * The alert's explanation: its rule's, a blocked new app's, an installed app's, a match
 * found in the history, or the kind of special access an app gained.
 */
fun explanationRes(alert: HistoryAlert): Int = when {
    alert.rule == AlertRule.FIRST_NETWORK_USE && alert.blocked() -> R.string.alert_first_network_use_blocked_text
    alert.rule == AlertRule.KNOWN_INDICATOR && alert.installedApp() -> R.string.alert_known_indicator_app_text
    alert.rule == AlertRule.KNOWN_INDICATOR && alert.past() -> R.string.alert_known_indicator_past_text
    alert.rule == AlertRule.SPECIAL_ACCESS -> when (alert.access()) {
        SpecialAccess.ACCESSIBILITY -> R.string.alert_accessibility_text
        SpecialAccess.DEVICE_ADMIN -> R.string.alert_device_admin_text
        SpecialAccess.NOTIFICATION_LISTENER -> R.string.alert_notification_access_text
        null -> explanationRes(alert.rule)
    }
    alert.rule == AlertRule.SENSOR_WHILE_AWAY -> when (alert.sensor()) {
        SensorKind.MICROPHONE -> R.string.alert_microphone_while_away_text
        SensorKind.CAMERA -> R.string.alert_camera_while_away_text
        null -> explanationRes(alert.rule)
    }
    else -> explanationRes(alert.rule)
}

fun titleRes(rule: AlertRule): Int = when (rule) {
    AlertRule.MONITORING_INTERRUPTED -> R.string.alert_monitoring_interrupted_title
    AlertRule.FIRST_NETWORK_USE -> R.string.alert_first_network_use_title
    AlertRule.NEW_DESTINATION -> R.string.alert_new_destination_title
    AlertRule.DNS_SERVERS_CHANGED -> R.string.alert_dns_servers_changed_title
    AlertRule.PRIVATE_DNS_CHANGED -> R.string.alert_private_dns_changed_title
    AlertRule.PROXY_CHANGED -> R.string.alert_proxy_changed_title
    AlertRule.KNOWN_INDICATOR -> R.string.alert_known_indicator_title
    AlertRule.SPECIAL_ACCESS -> R.string.alert_special_access_title
    AlertRule.REMOTE_ACCESS_EXPOSED -> R.string.alert_remote_access_exposed_title
    AlertRule.NEW_ROOT_CERTIFICATE -> R.string.alert_new_root_certificate_title
    AlertRule.SENSOR_WHILE_AWAY -> R.string.alert_sensor_while_away_title
    AlertRule.FLOW_LIMIT -> R.string.alert_flow_limit_title
    AlertRule.BEACON_LIKE -> R.string.alert_beacon_like_title
    AlertRule.DNS_TUNNEL -> R.string.alert_dns_tunnel_title
    AlertRule.OWN_ENCRYPTED_DNS -> R.string.alert_own_encrypted_dns_title
    AlertRule.UPLOAD_SURGE -> R.string.alert_upload_surge_title
    AlertRule.SHARING_SITE_UPLOAD -> R.string.alert_sharing_site_upload_title
    AlertRule.HISTORY_STARTED_ANEW -> R.string.alert_history_started_anew_title
    AlertRule.MONITORING_KEEPS_STOPPING -> R.string.alert_monitoring_keeps_stopping_title
}

fun explanationRes(rule: AlertRule): Int = when (rule) {
    AlertRule.MONITORING_INTERRUPTED -> R.string.alert_monitoring_interrupted_text
    AlertRule.FIRST_NETWORK_USE -> R.string.alert_first_network_use_text
    AlertRule.NEW_DESTINATION -> R.string.alert_new_destination_text
    AlertRule.DNS_SERVERS_CHANGED -> R.string.alert_dns_servers_changed_text
    AlertRule.PRIVATE_DNS_CHANGED -> R.string.alert_private_dns_changed_text
    AlertRule.PROXY_CHANGED -> R.string.alert_proxy_changed_text
    AlertRule.KNOWN_INDICATOR -> R.string.alert_known_indicator_text
    AlertRule.SPECIAL_ACCESS -> R.string.alert_special_access_text
    AlertRule.REMOTE_ACCESS_EXPOSED -> R.string.alert_remote_access_exposed_text
    AlertRule.NEW_ROOT_CERTIFICATE -> R.string.alert_new_root_certificate_text
    AlertRule.SENSOR_WHILE_AWAY -> R.string.alert_sensor_while_away_text
    AlertRule.FLOW_LIMIT -> R.string.alert_flow_limit_text
    AlertRule.BEACON_LIKE -> R.string.alert_beacon_like_text
    AlertRule.DNS_TUNNEL -> R.string.alert_dns_tunnel_text
    AlertRule.OWN_ENCRYPTED_DNS -> R.string.alert_own_encrypted_dns_text
    AlertRule.UPLOAD_SURGE -> R.string.alert_upload_surge_text
    AlertRule.SHARING_SITE_UPLOAD -> R.string.alert_sharing_site_upload_text
    AlertRule.HISTORY_STARTED_ANEW -> R.string.alert_history_started_anew_text
    AlertRule.MONITORING_KEEPS_STOPPING -> R.string.alert_monitoring_keeps_stopping_text
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
                    IndicatorSighting.SERVER_NAME,
                    IndicatorSighting.CONNECTION_NAME,
                    -> R.string.alert_evidence_indicator_tls
                    IndicatorSighting.ADDRESS -> R.string.alert_evidence_indicator_address
                    IndicatorSighting.INSTALLED_PACKAGE -> R.string.alert_evidence_indicator_package
                    IndicatorSighting.SIGNING_CERTIFICATE -> R.string.alert_evidence_indicator_certificate
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
        is AlertEvidence.PastConnections -> pastConnections(evidence)
        is AlertEvidence.Access -> stringResource(
            when (evidence.access) {
                SpecialAccess.ACCESSIBILITY -> R.string.alert_evidence_accessibility
                SpecialAccess.DEVICE_ADMIN -> R.string.alert_evidence_device_admin
                SpecialAccess.NOTIFICATION_LISTENER -> R.string.alert_evidence_notification_access
            },
        )
        is AlertEvidence.RemoteAccess -> when (evidence.service) {
            RemoteAccessService.WIRELESS_DEBUGGING -> stringResource(R.string.alert_evidence_wireless_debugging)
        }
        is AlertEvidence.Certificate -> stringResource(
            R.string.alert_evidence_certificate, isolate(evidence.subject), isolate(evidence.sha256),
        )
        is AlertEvidence.FlowLimit -> stringResource(R.string.alert_evidence_flow_limit, evidence.limit.toInt())
        is AlertEvidence.RepeatedGaps -> pluralStringResource(
            R.plurals.alert_evidence_repeated_gaps,
            evidence.count.toInt(),
            evidence.count.toInt(),
            evidence.hours.toInt(),
        )
        is AlertEvidence.Beacon -> stringResource(
            R.string.alert_evidence_beacon,
            isolate(evidence.destination),
            evidence.checkIns.toInt(),
            duration(evidence.intervalMs, LocalConfiguration.current.locales[0]),
            Formatter.formatShortFileSize(LocalContext.current, evidence.maxBytes.toLong()),
        )
        is AlertEvidence.DnsNames -> stringResource(
            R.string.alert_evidence_dns_names,
            evidence.names.toInt(),
            isolate(evidence.domain),
            isolate(evidence.example),
        )
        is AlertEvidence.DnsTxtLookups -> stringResource(R.string.alert_evidence_dns_txt, evidence.lookups.toInt())
        is AlertEvidence.EncryptedDns -> stringResource(R.string.alert_evidence_encrypted_dns, isolate(evidence.server))
        is AlertEvidence.UploadSurge -> stringResource(
            R.string.alert_evidence_upload_surge,
            Formatter.formatShortFileSize(LocalContext.current, evidence.lastDay.toLong()),
            evidence.days.toInt(),
            Formatter.formatShortFileSize(LocalContext.current, evidence.usualDay.toLong()),
        )
        is AlertEvidence.SharingSite -> stringResource(
            R.string.alert_evidence_sharing_site,
            Formatter.formatShortFileSize(LocalContext.current, evidence.bytesUp.toLong()),
            isolate(evidence.destination),
            stringResource(sharingSiteName(evidence.site)),
        )
        is AlertEvidence.Sensor -> {
            val started = DateFormat.getDateTimeInstance(
                DateFormat.SHORT, DateFormat.SHORT, LocalConfiguration.current.locales[0],
            ).format(Date(evidence.startedMs))
            listOfNotNull(
                stringResource(R.string.alert_evidence_sensor, stringResource(sensorName(evidence.sensor)), started),
                evidence.guess?.let { stringResource(R.string.alert_evidence_sensor_guess, isolate(label(it))) },
            ).joinToString(" ")
        }
    }

/** What a sharing service is for (DL-06). */
fun sharingSiteName(site: SharingSiteKind): Int = when (site) {
    SharingSiteKind.PASTE -> R.string.sharing_site_paste
    SharingSiteKind.FILE_SHARING -> R.string.sharing_site_file_sharing
    SharingSiteKind.ANONYMOUS_DROP -> R.string.sharing_site_anonymous_drop
}

/** How many connections the history holds, and on which days (MS-02). */
@Composable
private fun pastConnections(evidence: AlertEvidence.PastConnections): String {
    val format = DateFormat.getDateInstance(DateFormat.MEDIUM, LocalConfiguration.current.locales[0])
    val first = format.format(Date(evidence.firstMs))
    val last = format.format(Date(evidence.lastMs))
    val count = evidence.connections.toInt()
    return if (first == last) {
        pluralStringResource(R.plurals.alert_evidence_past_on, count, count, first)
    } else {
        pluralStringResource(R.plurals.alert_evidence_past_between, count, count, first, last)
    }
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
        is AlertAction.OpenAccessSettings -> stringResource(R.string.alert_action_open_access_settings)
        is AlertAction.OpenDeveloperSettings -> stringResource(R.string.alert_action_open_developer_settings)
        is AlertAction.OpenCertificateSettings -> stringResource(R.string.alert_action_open_certificate_settings)
        is AlertAction.OpenPrivacySettings -> stringResource(R.string.alert_action_open_privacy_settings)
        is AlertAction.OpenKeepRunning -> stringResource(R.string.keep_running_action)
    }
