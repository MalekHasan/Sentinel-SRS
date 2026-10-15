// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.Notification
import android.app.NotificationManager
import android.media.RingtoneManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertSeverity
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Alerts as notifications on a device (AL-01, AL-03, AL-04, AL-06), with the first rule:
 * a monitoring gap raises a Warning.
 */
@RunWith(AndroidJUnit4::class)
class AlertNotificationTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val manager = context.getSystemService(NotificationManager::class.java)

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        setDoNotDisturb(false)
        manager.cancelAll()
        History.wipe(context)
    }

    @After
    fun tearDown() {
        setDoNotDisturb(false)
        manager.cancelAll()
        History.wipe(context)
    }

    /** AL-01, AL-06: one channel per severity, each with its own importance and sound. */
    @Test
    fun eachSeverityHasItsOwnChannel() {
        AlertNotifier.createChannels(context)
        val channels = AlertSeverity.entries.associateWith {
            checkNotNull(manager.getNotificationChannel(AlertNotifier.channelId(it))) { "no channel for $it" }
        }
        assertEquals(NotificationManager.IMPORTANCE_LOW, channels.getValue(AlertSeverity.INFO).importance)
        assertEquals(NotificationManager.IMPORTANCE_DEFAULT, channels.getValue(AlertSeverity.WARNING).importance)
        assertEquals(NotificationManager.IMPORTANCE_HIGH, channels.getValue(AlertSeverity.HIGH).importance)
        assertEquals(NotificationManager.IMPORTANCE_HIGH, channels.getValue(AlertSeverity.CRITICAL).importance)
        assertNull("Info is silent", channels.getValue(AlertSeverity.INFO).sound)
        val chime = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
        val alarm = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM) ?: chime
        assertEquals(chime, channels.getValue(AlertSeverity.WARNING).sound)
        assertEquals(alarm, channels.getValue(AlertSeverity.CRITICAL).sound)
        val patterns = channels.values.mapNotNull { it.vibrationPattern?.toList() }
        assertEquals("distinct vibrations: $patterns", patterns.size, patterns.toSet().size)
        channels.values.forEach {
            assertEquals("${it.id} on the lock screen", Notification.VISIBILITY_PRIVATE, it.lockscreenVisibility)
        }
    }

    /** A gap posts one Warning notification that shows nothing on the lock screen. */
    @Test
    fun aMonitoringGapPostsAWarningNotification() {
        GapLog.open(context, System.currentTimeMillis(), "test reason")
        val posted = waitForAlertNotification()
        assertEquals(AlertNotifier.channelId(AlertSeverity.WARNING), posted.notification.channelId)
        assertEquals(
            context.getString(R.string.alert_monitoring_interrupted_title),
            posted.notification.extras.getCharSequence(Notification.EXTRA_TITLE)?.toString(),
        )
        assertEquals(Notification.VISIBILITY_PRIVATE, posted.notification.visibility)
        val public = checkNotNull(posted.notification.publicVersion)
        assertEquals(
            context.getString(R.string.alert_notification_public),
            public.extras.getCharSequence(Notification.EXTRA_TITLE)?.toString(),
        )
        assertNotNull("tapping opens the alert", posted.notification.contentIntent)
        assertNotNull(History.get(context).alerts(true, 10u).single().notifiedMs)
    }

    /** AL-03: repeated alerts share one notification, and three an hour are notified. */
    @Test
    fun repeatedAlertsShareOneNotificationAndStopAtThreeAnHour() {
        repeat(5) { gap ->
            GapLog.open(context, gap * 1_000L, "gap $gap")
            GapLog.closeOpen(context, gap * 1_000L + 500)
        }
        val alerts = History.get(context).alerts(true, 10u)
        assertEquals(5, alerts.size)
        assertEquals("notified", 3, alerts.count { it.notifiedMs != null })
        val posted = waitForAlertNotification()
        assertEquals(
            "one notification for the five",
            1,
            manager.activeNotifications.count { it.id == AlertNotifier.NOTIFICATION_ID },
        )
        // The third alert was the last notified: two more like it were open then.
        val more = context.resources.getQuantityString(R.plurals.alert_more_like_this, 2, 2)
        val text = posted.notification.extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString().orEmpty()
        assertTrue(text, text.endsWith(more))
    }

    /** AL-04: while Do Not Disturb is on, a Warning waits in the app. */
    @Test
    fun doNotDisturbKeepsAWarningInTheApp() {
        setDoNotDisturb(true)
        GapLog.open(context, System.currentTimeMillis(), "quiet")
        val alert = History.get(context).alerts(true, 10u).single()
        assertNull("not notified", alert.notifiedMs)
        Thread.sleep(500)
        assertTrue(manager.activeNotifications.none { it.id == AlertNotifier.NOTIFICATION_ID })
    }

    private fun waitForAlertNotification() =
        run {
            waitFor("the alert notification") {
                manager.activeNotifications.any { it.id == AlertNotifier.NOTIFICATION_ID }
            }
            manager.activeNotifications.first { it.id == AlertNotifier.NOTIFICATION_ID }
        }

    private fun setDoNotDisturb(on: Boolean) {
        shell("cmd notification set_dnd ${if (on) "priority" else "off"}")
        waitFor("Do Not Disturb ${if (on) "on" else "off"}") {
            (manager.currentInterruptionFilter == NotificationManager.INTERRUPTION_FILTER_ALL) != on
        }
    }
}
