// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.malekhasan.sentinel.core.EngineSnapshot
import io.github.malekhasan.sentinel.core.coreVersion
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    /** True between onStart and onStop: live counters refresh only while visible. */
    private val visible = mutableStateOf(false)

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) startMonitoring()
        }

    // Monitoring starts whatever the answer: the notification is wanted, not required.
    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { askVpnConsent() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        GapLog.recordUnexpectedExit(this)
        // Calls into the Rust core through UniFFI: proves the native library loads.
        val version = coreVersion()
        setContent {
            SentinelTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    MonitorScreen(
                        coreVersion = version,
                        visible = visible.value,
                        onStart = ::requestStart,
                        onStop = ::stopMonitoring,
                    )
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        visible.value = true
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
fun MonitorScreen(coreVersion: String, visible: Boolean, onStart: () -> Unit, onStop: () -> Unit) {
    val context = LocalContext.current
    val status by Monitor.status.collectAsState()
    var snapshot by remember { mutableStateOf<EngineSnapshot?>(null) }
    var gaps by remember { mutableStateOf(emptyList<GapLog.Gap>()) }

    LaunchedEffect(visible, status) {
        gaps = withContext(Dispatchers.IO) { GapLog.recent(context, 5) }
        snapshot = null
        while (visible && status == Monitor.Status.ON) {
            snapshot = Monitor.snapshot()
            delay(1_000)
        }
    }

    Column(
        modifier = Modifier
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
        Text(stringResource(R.string.tagline), style = MaterialTheme.typography.bodyLarge)

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
                OutlinedButton(onClick = onStop) { Text(stringResource(R.string.action_stop)) }
            }
        }

        if (gaps.isNotEmpty()) {
            Text(stringResource(R.string.gaps_title), style = MaterialTheme.typography.titleSmall)
            gaps.forEach { gap -> Text(describeGap(gap), style = MaterialTheme.typography.bodySmall) }
        }

        Text(
            stringResource(R.string.core_version, coreVersion),
            style = MaterialTheme.typography.labelMedium,
        )
    }
}

@Composable
private fun describeGap(gap: GapLog.Gap): String {
    val format = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
    val start = gap.startMillis?.let { format.format(Date(it)) }
        ?: stringResource(R.string.gap_time_unknown)
    return when (val end = gap.endMillis) {
        null -> stringResource(R.string.gap_open, start, gap.reason)
        else -> stringResource(R.string.gap_closed, start, format.format(Date(end)), gap.reason)
    }
}
