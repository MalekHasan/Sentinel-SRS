// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.format.Formatter
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.AlertAction
import io.github.malekhasan.sentinel.core.EngineSnapshot
import io.github.malekhasan.sentinel.core.FirewallMode
import io.github.malekhasan.sentinel.core.HistoryAlert
import io.github.malekhasan.sentinel.core.HistoryAway
import io.github.malekhasan.sentinel.core.HistoryFlow
import io.github.malekhasan.sentinel.core.KnownTraces
import io.github.malekhasan.sentinel.core.coreVersion
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    /** True between onStart and onStop: live counters refresh only while visible. */
    private val visible = mutableStateOf(false)

    /** The alert a tapped notification asks to show (AL-06). */
    private val requestedAlert = mutableStateOf<Long?>(null)

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) startMonitoring()
        }

    // Monitoring starts whatever the answer: the notification is wanted, not required.
    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { askVpnConsent() }

    // A folder holding an indicator list, for phones that cannot reach where it is
    // published (MS-10).
    private val importFeed =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { tree ->
            if (tree != null) {
                Thread({ IndicatorFeed.importFrom(this, tree) }, "sentinel-feed-import").start()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        GapLog.recordUnexpectedExit(this)
        FeedUpdateJob.schedule(this)
        if (savedInstanceState == null) showRequestedAlert(intent)
        // Calls into the Rust core through UniFFI: proves the native library loads.
        val version = coreVersion()
        setContent {
            val scope = rememberCoroutineScope()
            var showLive by rememberSaveable { mutableStateOf(false) }
            var showJournal by rememberSaveable { mutableStateOf(false) }
            // The app whose detail is open, over whichever screen opened it.
            var openApp by rememberSaveable { mutableStateOf<String?>(null) }
            // The alert that is open; an app opened from it shows over it.
            var openAlert by rememberSaveable { mutableStateOf<Long?>(null) }
            LaunchedEffect(requestedAlert.value) {
                requestedAlert.value?.let {
                    openApp = null
                    showLive = false
                    showJournal = false
                    openAlert = it
                    requestedAlert.value = null
                }
            }
            SentinelTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val detail = openApp
                    val alert = openAlert
                    when {
                        detail != null -> {
                            BackHandler { openApp = null }
                            AppDetailScreen(app = detail, visible = visible.value, onBack = { openApp = null })
                        }
                        alert != null -> {
                            BackHandler { openAlert = null }
                            AlertDetailScreen(
                                id = alert,
                                onBack = { openAlert = null },
                                onAction = { action ->
                                    when (action) {
                                        is AlertAction.StartMonitoring -> {
                                            openAlert = null
                                            requestStart()
                                        }
                                        is AlertAction.OpenApp -> openApp = action.app
                                        is AlertAction.OpenNetworkSettings ->
                                            startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
                                        is AlertAction.AllowApp -> scope.launch { allow(action.app, alert) }
                                        is AlertAction.BlockApp -> scope.launch { block(action.app, alert) }
                                    }
                                },
                            )
                        }
                        showJournal -> {
                            BackHandler { showJournal = false }
                            JournalScreen(onBack = { showJournal = false })
                        }
                        showLive -> {
                            BackHandler { showLive = false }
                            LiveConnectionsScreen(
                                visible = visible.value,
                                onBack = { showLive = false },
                                onOpenApp = { openApp = it },
                            )
                        }
                        else -> MonitorScreen(
                            coreVersion = version,
                            visible = visible.value,
                            onStart = ::requestStart,
                            onStop = ::stopMonitoring,
                            onShowLive = { showLive = true },
                            onShowJournal = { showJournal = true },
                            onImportFeed = { importFeed.launch(null) },
                            onOpenApp = { openApp = it },
                            onOpenAlert = { openAlert = it },
                        )
                    }
                }
            }
        }
    }

    /** Lets [app] use the internet (CM-08), as alert [fromAlert] offered, and says so. */
    private suspend fun allow(app: String, fromAlert: Long) =
        firewallAction(app, fromAlert, R.string.firewall_app_allowed, ::allowApp)

    /** Stops [app] using the internet (RA-01), as alert [fromAlert] offered, and says so. */
    private suspend fun block(app: String, fromAlert: Long) =
        firewallAction(app, fromAlert, R.string.firewall_app_blocked, ::blockApp)

    private suspend fun firewallAction(
        app: String,
        fromAlert: Long,
        done: Int,
        act: (Context, String, Long?) -> Boolean,
    ) {
        val label = withContext(Dispatchers.IO) {
            if (act(this@MainActivity, app, fromAlert)) AppNames(this@MainActivity).labelFor(app) else null
        }
        if (label != null) {
            Toast.makeText(this, getString(done, isolate(label)), Toast.LENGTH_LONG).show()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        showRequestedAlert(intent)
    }

    private fun showRequestedAlert(intent: Intent?) {
        val id = intent?.getLongExtra(AlertNotifier.EXTRA_ALERT_ID, -1L) ?: -1L
        if (id >= 0) requestedAlert.value = id
    }

    override fun onStart() {
        super.onStart()
        visible.value = true
        // A new list as soon as the app opens, when one is due (MS-10). Then the history
        // is checked against the list in force, should that not have been done (MS-02),
        // and the installed apps, which may have changed since (ID-13).
        Thread({
            if (IndicatorFeed.get(this) != null && IndicatorFeed.checkDue(this)) {
                IndicatorFeed.checkPublished(this)
            }
            History.hunt(this)
            InstalledApps.check(this)
        }, "sentinel-feed-check").start()
    }

    override fun onStop() {
        visible.value = false
        super.onStop()
    }

    private fun requestStart() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            askVpnConsent()
        }
    }

    /** Android shows its own VPN consent dialog the first time (SRS §15.3: no hidden mode). */
    private fun askVpnConsent() {
        val consent = VpnService.prepare(this)
        if (consent == null) startMonitoring() else vpnConsent.launch(consent)
    }

    private fun startMonitoring() {
        startForegroundService(
            Intent(this, SentinelVpnService::class.java).setAction(SentinelVpnService.ACTION_START),
        )
    }

    private fun stopMonitoring() {
        startService(
            Intent(this, SentinelVpnService::class.java).setAction(SentinelVpnService.ACTION_STOP),
        )
    }
}

@Composable
fun SentinelTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()
    MaterialTheme(colorScheme = colors, content = content)
}

@Composable
fun MonitorScreen(
    coreVersion: String,
    visible: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onShowLive: () -> Unit,
    onOpenApp: (String) -> Unit,
    onOpenAlert: (Long) -> Unit,
    onShowJournal: () -> Unit,
    onImportFeed: () -> Unit,
) {
    val context = LocalContext.current
    val status by Monitor.status.collectAsState()
    val feed by IndicatorFeed.states.collectAsState()
    val hunts by History.hunts.collectAsState()
    var traces by remember { mutableStateOf<KnownTraces?>(null) }
    var snapshot by remember { mutableStateOf<EngineSnapshot?>(null) }
    var flows by remember { mutableStateOf(emptyList<HistoryFlow>()) }
    var gaps by remember { mutableStateOf(emptyList<GapLog.Gap>()) }
    var away by remember { mutableStateOf(emptyList<AwayRow>()) }
    var alerts by remember { mutableStateOf(emptyList<HistoryAlert>()) }
    var mode by remember { mutableStateOf<FirewallMode?>(null) }
    var isolated by remember { mutableStateOf<Long?>(null) }
    val names = remember(context) { AppNames(context) }
    val scope = rememberCoroutineScope()
    var confirmWipe by remember { mutableStateOf(false) }
    // Bumped after a wipe so the lists reload.
    var generation by remember { mutableIntStateOf(0) }

    // Opening the feed checks the list in force (SP-04).
    LaunchedEffect(Unit) { withContext(Dispatchers.IO) { IndicatorFeed.get(context) } }

    LaunchedEffect(visible, status, generation, hunts, feed.status?.version) {
        suspend fun reload() {
            traces = withContext(Dispatchers.IO) { History.knownTraces(context) }
            flows = withContext(Dispatchers.IO) { recentFlows(context) }
            gaps = withContext(Dispatchers.IO) { GapLog.recent(context, 5) }
            away = withContext(Dispatchers.IO) { awayRows(context, names) }
            alerts = withContext(Dispatchers.IO) { openAlerts(context, ALERTS_SHOWN) }
            mode = withContext(Dispatchers.IO) { firewallMode(context) }
            isolated = withContext(Dispatchers.IO) { isolatedSince(context) }
        }
        snapshot = null
        reload()
        while (visible && status == Monitor.Status.ON) {
            snapshot = Monitor.snapshot()
            reload()
            delay(1_000)
        }
    }

    if (confirmWipe) {
        AlertDialog(
            onDismissRequest = { confirmWipe = false },
            title = { Text(stringResource(R.string.wipe_title)) },
            text = { Text(stringResource(R.string.wipe_text)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmWipe = false
                    // Refused if monitoring started meanwhile; the button then hides.
                    runCatching { History.wipe(context) }
                    generation++
                }) { Text(stringResource(R.string.wipe_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmWipe = false }) {
                    Text(stringResource(R.string.wipe_cancel))
                }
            },
        )
    }

    MonitorContent(
        coreVersion = coreVersion,
        status = status,
        snapshot = snapshot,
        flows = flows,
        gaps = gaps,
        away = away,
        alerts = alerts,
        onStart = onStart,
        onStop = onStop,
        onShowLive = onShowLive,
        onOpenApp = onOpenApp,
        onOpenAlert = onOpenAlert,
        onWipe = { confirmWipe = true },
        isolatedSince = isolated,
        onIsolate = {
            scope.launch {
                isolated = withContext(Dispatchers.IO) {
                    isolatePhone(context)
                    isolatedSince(context)
                }
            }
        },
        onEndIsolation = {
            scope.launch {
                isolated = withContext(Dispatchers.IO) {
                    endIsolation(context)
                    isolatedSince(context)
                }
            }
        },
        onShowJournal = onShowJournal,
        feed = feed,
        traces = traces,
        onCheckFeed = { scope.launch(Dispatchers.IO) { IndicatorFeed.checkPublished(context) } },
        onImportFeed = onImportFeed,
        firewallMode = mode,
        onFirewallMode = { chosen ->
            scope.launch {
                mode = withContext(Dispatchers.IO) {
                    setFirewallMode(context, chosen)
                    firewallMode(context)
                }
            }
        },
    )
}

/** The main screen's content, without its loading (so tests can render any state). */
@Composable
fun MonitorContent(
    coreVersion: String,
    status: Monitor.Status,
    snapshot: EngineSnapshot?,
    flows: List<HistoryFlow>,
    gaps: List<GapLog.Gap>,
    away: List<AwayRow>,
    alerts: List<HistoryAlert>,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onShowLive: () -> Unit,
    onOpenApp: (String) -> Unit,
    onOpenAlert: (Long) -> Unit,
    onWipe: () -> Unit,
    firewallMode: FirewallMode? = null,
    onFirewallMode: (FirewallMode) -> Unit = {},
    isolatedSince: Long? = null,
    onIsolate: () -> Unit = {},
    onEndIsolation: () -> Unit = {},
    onShowJournal: () -> Unit = {},
    feed: IndicatorFeed.State? = null,
    onCheckFeed: () -> Unit = {},
    onImportFeed: () -> Unit = {},
    traces: KnownTraces? = null,
) {
    val context = LocalContext.current
    Column(
        modifier = Modifier
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
        Text(stringResource(R.string.tagline), style = MaterialTheme.typography.bodyLarge)

        // Isolation first: while it is on, almost nothing reaches the internet (RA-03).
        if (isolatedSince != null) {
            Isolated(isolatedSince, monitoring = status == Monitor.Status.ON, onEndIsolation)
        }

        // Open alerts first: they are what needs the user (AL-01, AL-02).
        if (alerts.isNotEmpty()) {
            Text(stringResource(R.string.alerts_title), style = MaterialTheme.typography.titleMedium)
            alerts.forEach { AlertRow(it, onOpenAlert) }
        }

        when (status) {
            Monitor.Status.OFF -> {
                Text(stringResource(R.string.status_off), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.disclosure), style = MaterialTheme.typography.bodyMedium)
                Button(onClick = onStart) { Text(stringResource(R.string.action_start)) }
            }
            Monitor.Status.STARTING -> {
                Text(stringResource(R.string.status_starting), style = MaterialTheme.typography.titleMedium)
            }
            Monitor.Status.ON -> {
                Text(stringResource(R.string.status_on), style = MaterialTheme.typography.titleMedium)
                snapshot?.let {
                    Text(
                        stringResource(
                            R.string.stats,
                            it.flowsTotal.toLong(),
                            it.flowsActive.toLong(),
                            it.upstreamFailures.toLong(),
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                Button(onClick = onShowLive) { Text(stringResource(R.string.live_action)) }
                OutlinedButton(onClick = onStop) { Text(stringResource(R.string.action_stop)) }
                if (isolatedSince == null) {
                    OutlinedButton(onClick = onIsolate) { Text(stringResource(R.string.isolation_start)) }
                    Text(stringResource(R.string.isolation_start_text), style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        // Kept in the history, so it can be chosen before monitoring starts (CM-08).
        FirewallModeChoice(firewallMode, onFirewallMode)
        // Every change to the firewall, with Undo (SRS §9).
        OutlinedButton(onClick = onShowJournal) { Text(stringResource(R.string.journal_action)) }

        // What known spyware and stalkerware is looked for, and from when (MS-10).
        feed?.let { IndicatorList(it, onCheckFeed, onImportFeed, traces) }

        if (away.isNotEmpty()) {
            Text(stringResource(R.string.away_title), style = MaterialTheme.typography.titleSmall)
            away.forEach { row ->
                val app = row.away.app
                Text(
                    stringResource(
                        R.string.away_app,
                        isolate(row.label ?: stringResource(R.string.unknown_app)),
                        Formatter.formatShortFileSize(context, row.away.bytesUpAway),
                        Formatter.formatShortFileSize(context, row.away.bytesDownAway),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.clickable(enabled = app != null) { app?.let(onOpenApp) },
                )
            }
        }

        if (flows.isNotEmpty()) {
            Text(stringResource(R.string.recent_title), style = MaterialTheme.typography.titleSmall)
            flows.forEach { flow ->
                val app = flow.app
                Text(
                    describeFlow(flow),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.clickable(enabled = app != null) { app?.let(onOpenApp) },
                )
            }
        }

        if (gaps.isNotEmpty()) {
            Text(stringResource(R.string.gaps_title), style = MaterialTheme.typography.titleSmall)
            gaps.forEach { gap -> Text(describeGap(gap), style = MaterialTheme.typography.bodySmall) }
        }

        // The engine writes to the history while it runs, so it can only be deleted
        // while monitoring is off.
        if (status == Monitor.Status.OFF && (flows.isNotEmpty() || gaps.isNotEmpty())) {
            OutlinedButton(onClick = onWipe) {
                Text(stringResource(R.string.wipe_action))
            }
        }

        Text(
            stringResource(R.string.core_version, isolate(coreVersion)),
            style = MaterialTheme.typography.labelMedium,
        )
    }
}

/** That the phone is isolated, since when, and how to end it (RA-03). */
@Composable
private fun Isolated(since: Long, monitoring: Boolean, onEnd: () -> Unit) {
    val format = DateFormat.getDateTimeInstance(
        DateFormat.SHORT, DateFormat.SHORT, LocalConfiguration.current.locales[0],
    )
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.isolation_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.isolation_text, format.format(Date(since))), style = MaterialTheme.typography.bodyMedium)
            if (!monitoring) {
                Text(stringResource(R.string.isolation_off_note), style = MaterialTheme.typography.bodyMedium)
            }
            Button(onClick = onEnd) { Text(stringResource(R.string.isolation_end)) }
        }
    }
}

/** Open alerts listed on the main screen, newest first. */
private const val ALERTS_SHOWN = 5u

/** An app's traffic while the user was away, with the name the user knows it by. */
data class AwayRow(val away: HistoryAway, val label: String?)

/** Apps listed under "while away", and how far back they are counted (CM-06). */
private const val AWAY_SHOWN = 5u
private const val AWAY_WINDOW_MILLIS = 24 * 60 * 60 * 1000L

private fun awayRows(context: Context, names: AppNames): List<AwayRow> =
    try {
        History.get(context)
            .awayTotals(System.currentTimeMillis() - AWAY_WINDOW_MILLIS, AWAY_SHOWN)
            .map { AwayRow(it, it.app?.let(names::labelFor)) }
    } catch (e: Exception) {
        emptyList()
    }

/** Flows listed on the main screen; open connections by app are in the live view. */
private const val RECENT_SHOWN = 20u

private fun recentFlows(context: Context): List<HistoryFlow> =
    try {
        History.get(context).recentFlows(RECENT_SHOWN)
    } catch (e: Exception) {
        emptyList()
    }

@Composable
private fun describeFlow(flow: HistoryFlow): String {
    val app = flow.app ?: stringResource(R.string.unknown_app)
    val destination = hostAndPort(flow.hostname ?: flow.remoteIp, flow.remotePort.toInt())
    return stringResource(
        if (flow.endedMs == null) R.string.flow_open else R.string.flow_closed,
        isolate(app),
        isolate(destination),
    )
}

@Composable
private fun describeGap(gap: GapLog.Gap): String {
    val format = DateFormat.getDateTimeInstance(
        DateFormat.SHORT, DateFormat.SHORT, LocalConfiguration.current.locales[0],
    )
    val start = gap.startMillis?.let { format.format(Date(it)) }
        ?: stringResource(R.string.gap_time_unknown)
    return when (val end = gap.endMillis) {
        null -> stringResource(R.string.gap_open, start, gap.reason)
        else -> stringResource(R.string.gap_closed, start, format.format(Date(end)), gap.reason)
    }
}
