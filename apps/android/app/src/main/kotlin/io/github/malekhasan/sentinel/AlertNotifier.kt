// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.os.Build
import android.util.Log
import io.github.malekhasan.sentinel.core.AlertDelivery
import io.github.malekhasan.sentinel.core.AlertEvidence
import io.github.malekhasan.sentinel.core.AlertListener
import io.github.malekhasan.sentinel.core.AlertSeverity
import io.github.malekhasan.sentinel.core.HistoryAlert
import io.github.malekhasan.sentinel.core.HistoryStore

/**
 * Alerts as notifications (AL-06). Each severity has its own channel, with its own
 * importance, sound and vibration (AL-01). The core decides whether an alert is
 * notified now: at most three non-critical notifications an hour per app (AL-03), and
 * Info and Warning wait in the app while Do Not Disturb is on (AL-04). Repeated alerts
 * of one kind share one notification, which says how many more are open (AL-03). On a
 * locked phone a notification makes its sound but shows nothing (ADR-0012).
 */
object AlertNotifier {
    private const val TAG = "SentinelAlertNotifier"

    /** Notification id of every alert; the tag tells kinds of alert apart. */
    const val NOTIFICATION_ID = 2

    /** Extra of the intent a notification opens: the alert to show. */
    const val EXTRA_ALERT_ID = "io.github.malekhasan.sentinel.ALERT_ID"

    /** Open alerts counted for "more like this". */
    private const val COUNTED = 100u

    fun channelId(severity: AlertSeverity): String = "alert-${severity.name.lowercase()}"

    /** Alerts of one rule about one app share a notification. */
    fun groupKey(alert: HistoryAlert): String {
        val app = alert.evidence.filterIsInstance<AlertEvidence.App>().firstOrNull()?.app.orEmpty()
        return "${alert.rule.name}:$app"
    }

    /** Hears the core's new alerts. */
    class Listener(private val context: Context) : AlertListener {
        override fun raised(alert: HistoryAlert) = deliver(context, History.get(context), alert)
    }

    /**
     * Creates the four channels, or renames them in the current language. Android keeps
     * a channel's sound and importance once created, and the user's changes to them.
     */
    fun createChannels(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        val audio = AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_NOTIFICATION)
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build()
        val chime = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
        val alarm = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM) ?: chime
        for (severity in AlertSeverity.entries) {
            val (importance, name, description) = when (severity) {
                AlertSeverity.INFO -> Triple(
                    NotificationManager.IMPORTANCE_LOW, R.string.channel_alert_info, R.string.channel_alert_info_description,
                )
                AlertSeverity.WARNING -> Triple(
                    NotificationManager.IMPORTANCE_DEFAULT, R.string.channel_alert_warning,
                    R.string.channel_alert_warning_description,
                )
                AlertSeverity.HIGH -> Triple(
                    NotificationManager.IMPORTANCE_HIGH, R.string.channel_alert_high, R.string.channel_alert_high_description,
                )
                AlertSeverity.CRITICAL -> Triple(
                    NotificationManager.IMPORTANCE_HIGH, R.string.channel_alert_critical,
                    R.string.channel_alert_critical_description,
                )
            }
            val channel = NotificationChannel(channelId(severity), context.getString(name), importance).apply {
                this.description = context.getString(description)
                when (severity) {
                    AlertSeverity.INFO -> {
                        setSound(null, null)
                        enableVibration(false)
                    }
                    AlertSeverity.WARNING -> {
                        setSound(chime, audio)
                        vibrationPattern = longArrayOf(0, 200)
                    }
                    AlertSeverity.HIGH -> {
                        setSound(chime, audio)
                        vibrationPattern = longArrayOf(0, 300, 150, 300)
                        // Asks to come through Do Not Disturb; Android grants it only if
                        // the user allows Sentinel there (AL-04).
                        setBypassDnd(true)
                    }
                    AlertSeverity.CRITICAL -> {
                        setSound(alarm, audio)
                        vibrationPattern = longArrayOf(0, 600, 200, 600, 200, 600)
                        setBypassDnd(true)
                    }
                }
            }
            manager.createNotificationChannel(channel)
        }
    }

    /** Notify [alert] now if the core allows it; otherwise it waits in the app. */
    fun deliver(context: Context, history: HistoryStore, alert: HistoryAlert) {
        try {
            val manager = context.getSystemService(NotificationManager::class.java)
            createChannels(context)
            // A notification Android would not show must not use up the allowance.
            val permitted = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
                context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
            val channel = manager.getNotificationChannel(channelId(alert.severity))
            if (!permitted || !manager.areNotificationsEnabled() ||
                channel?.importance == NotificationManager.IMPORTANCE_NONE
            ) {
                return
            }
            val filter = manager.currentInterruptionFilter
            val doNotDisturb = filter != NotificationManager.INTERRUPTION_FILTER_ALL &&
                filter != NotificationManager.INTERRUPTION_FILTER_UNKNOWN
            if (history.claimNotification(alert.id, doNotDisturb) == AlertDelivery.NOTIFY) {
                val alike = history.alerts(true, COUNTED).count { groupKey(it) == groupKey(alert) }
                manager.notify(groupKey(alert), NOTIFICATION_ID, build(context, alert, alike))
            }
        } catch (e: Exception) {
            // A failed notification must never stop what raised the alert.
            Log.w(TAG, "could not notify alert ${alert.id}", e)
        }
    }

    private fun build(context: Context, alert: HistoryAlert, alike: Int): Notification {
        val text = context.getString(explanationRes(alert))
        val more = alike - 1
        val details = if (more > 0) {
            text + "\n" + context.resources.getQuantityString(R.plurals.alert_more_like_this, more, more)
        } else {
            text
        }
        val open = PendingIntent.getActivity(
            context,
            alert.id.toInt(),
            Intent(context, MainActivity::class.java)
                .putExtra(EXTRA_ALERT_ID, alert.id)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(context, channelId(alert.severity))
            .setSmallIcon(R.drawable.ic_monitoring)
            .setContentTitle(context.getString(titleRes(alert)))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(details))
            .setSubText(context.getString(severityNameRes(alert.severity)))
            .setContentIntent(open)
            .setAutoCancel(true)
            // Nothing on a locked phone, whatever the lock screen setting: what was found
            // can matter to someone who looks at the phone. It still sounds.
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
    }
}
