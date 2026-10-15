// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.icu.text.ListFormatter
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
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.HistoryApp
import io.github.malekhasan.sentinel.core.HistoryCompany
import io.github.malekhasan.sentinel.core.HistoryDestination
import io.github.malekhasan.sentinel.core.NameSource
import java.text.DateFormat
import java.util.Date
import java.util.Locale
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
                val format = DateFormat.getDateTimeInstance(
                    DateFormat.SHORT, DateFormat.SHORT, LocalConfiguration.current.locales[0],
                )
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
        if (history.companies.isNotEmpty()) {
            item {
                Text(stringResource(R.string.app_detail_companies_title), style = MaterialTheme.typography.titleSmall)
            }
            // Destination keys are hostnames or addresses, which never start with "company:".
            items(history.companies, key = { "company:${it.company}" }) { CompanyRow(it) }
            item {
                Text(stringResource(R.string.app_detail_companies_note), style = MaterialTheme.typography.bodySmall)
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

/** One company the app's destinations belong to, from the tracker lists (DT-06). */
@Composable
private fun CompanyRow(company: HistoryCompany) {
    val context = LocalContext.current
    val count = company.destinations.toInt()
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(company.company, style = MaterialTheme.typography.titleSmall)
        if (company.categories.isNotEmpty()) {
            Text(categoryList(company.categories), style = MaterialTheme.typography.bodySmall)
        }
        Text(
            pluralStringResource(R.plurals.company_destinations, count, count),
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            stringResource(
                R.string.traffic,
                Formatter.formatShortFileSize(context, company.bytesUp),
                Formatter.formatShortFileSize(context, company.bytesDown),
            ),
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun DestinationRow(destination: HistoryDestination) {
    val context = LocalContext.current
    val flows = destination.flows.toInt()
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(destination.destination, style = MaterialTheme.typography.titleSmall)
        DestinationFacts(destination)
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

/**
 * What is known about a destination and why we believe it (SRS DT-02): how its name was
 * learned, its company and kind of service (DT-06), its network and its country, each
 * with its source and how far to trust it.
 */
@Composable
private fun DestinationFacts(destination: HistoryDestination) {
    val small = MaterialTheme.typography.bodySmall
    val why = MaterialTheme.typography.labelSmall
    when {
        destination.nameSource == NameSource.SNI -> Text(stringResource(R.string.dest_named_sni), style = why)
        destination.nameSource == NameSource.DNS -> Text(stringResource(R.string.dest_named_dns), style = why)
        android.net.InetAddresses.isNumericAddress(destination.destination) ->
            Text(stringResource(R.string.dest_address_only), style = why)
    }
    destination.company?.let { fact ->
        Text(stringResource(R.string.dest_company, isolate(fact.company)), style = small)
        Text(listedWhy(fact.sources, fact.listedDomain), style = why)
    }
    destination.categories?.let { fact ->
        Text(stringResource(R.string.dest_categories, categoryList(fact.categories)), style = small)
        Text(listedWhy(fact.sources, fact.listedDomain), style = why)
    }
    destination.asn?.let { asn ->
        val network = listOfNotNull("AS$asn", destination.networkOwner).joinToString(" ")
        Text(stringResource(R.string.dest_network, isolate(network)), style = small)
        destination.networkSource?.let {
            Text(stringResource(R.string.dest_network_why, isolate(it)), style = why)
        }
    }
    destination.country?.let { code ->
        Text(stringResource(R.string.dest_country, countryName(code)), style = small)
        destination.countrySource?.let {
            Text(stringResource(R.string.dest_country_why, isolate(it)), style = why)
        }
    }
}

/** Where an answer from the tracker lists comes from: the lists, and the entry. */
@Composable
private fun listedWhy(sources: List<String>, listedDomain: String): String {
    val lists = ListFormatter.getInstance(LocalConfiguration.current.locales[0]).format(sources.map(::isolate))
    return stringResource(R.string.dest_listed_why, lists, isolate(listedDomain))
}

/** Categories in the screen's language where the app knows them, as the list names them
 *  otherwise. */
@Composable
private fun categoryList(categories: List<String>): String {
    val names = categories.map { raw -> CATEGORY_NAMES[raw]?.let { stringResource(it) } ?: isolate(raw) }
    return ListFormatter.getInstance(LocalConfiguration.current.locales[0]).format(names)
}

/** Tracker Radar's categories, by the name the list uses. */
private val CATEGORY_NAMES = mapOf(
    "Ad Motivated Tracking" to R.string.category_ad_motivated_tracking,
    "Ad Fraud" to R.string.category_ad_fraud,
    "Advertising" to R.string.category_advertising,
    "Analytics" to R.string.category_analytics,
    "Audience Measurement" to R.string.category_audience_measurement,
    "Action Pixels" to R.string.category_action_pixels,
    "Badge" to R.string.category_badge,
    "CDN" to R.string.category_cdn,
    "Consent Management Platform" to R.string.category_consent_management,
    "Embedded Content" to R.string.category_embedded_content,
    "Federated Login" to R.string.category_federated_login,
    "Fraud Prevention" to R.string.category_fraud_prevention,
    "Malware" to R.string.category_malware,
    "Non-Tracking" to R.string.category_non_tracking,
    "Obscure Ownership" to R.string.category_obscure_ownership,
    "Online Payment" to R.string.category_online_payment,
    "Session Replay" to R.string.category_session_replay,
    "Social - Comment" to R.string.category_social_comment,
    "Social - Share" to R.string.category_social_share,
    "Social Network" to R.string.category_social_network,
    "SSO" to R.string.category_sso,
    "Support Chat Widget" to R.string.category_support_chat,
    "Tag Manager" to R.string.category_tag_manager,
    "Third-Party Analytics Marketing" to R.string.category_third_party_analytics_marketing,
    "Unknown High Risk Behavior" to R.string.category_unknown_high_risk,
)

/** The country's name in the screen's language, or its code if Android has none. */
@Composable
fun countryName(code: String): String {
    val locale = LocalConfiguration.current.locales[0]
    return Locale.Builder().setRegion(code).build().getDisplayCountry(locale).ifEmpty { code }
}
