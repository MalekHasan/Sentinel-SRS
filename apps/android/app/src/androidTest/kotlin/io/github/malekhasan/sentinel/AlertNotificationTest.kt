// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.Notification
import android.app.NotificationManager
import android.media.RingtoneManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.AlertRule
import io.github.malekhasan.sentinel.core.AlertSeverity
import io.github.malekhasan.sentinel.core.HeldAccess
import io.github.malekhasan.sentinel.core.SpecialAccess
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
    }

    /** A gap posts one Warning notification that shows nothing on a locked phone. */
    @Test
    fun aMonitoringGapPostsAWarningNotification() {
        GapLog.open(context, System.currentTimeMillis(), "test reason")
        val posted = waitForAlertNotification()
        assertEquals(AlertNotifier.channelId(AlertSeverity.WARNING), posted.notification.channelId)
        assertEquals(
            context.getString(R.string.alert_monitoring_interrupted_title),
            posted.notification.extras.getCharSequence(Notification.EXTRA_TITLE)?.toString(),
        )
        assertEquals(Notification.VISIBILITY_SECRET, posted.notification.visibility)
        assertNotNull("tapping opens the alert", posted.notification.contentIntent)
        assertNotNull(History.get(context).alerts(true, 10u).single().notifiedMs)
    }

    /**
     * Audit A-10: an alert about signs of someone watching the phone says only that there
     * is something to review, for spyware that reads notifications sees them too. Its
     * title, explanation, severity and app show in the app only, and the notification's
     * tag names neither the rule nor the app.
     */
    @Test
    fun anAlertAboutSpyingSaysOnlyThatThereIsSomethingToReview() {
        val spy = "org.example.watcher"
        History.get(context).checkAccess(listOf(HeldAccess(spy, SpecialAccess.ACCESSIBILITY, false)))
        val posted = waitForAlertNotification()
        val alert = History.get(context).alerts(true, 10u).single()
        assertEquals(AlertRule.SPECIAL_ACCESS, alert.rule)
        assertNotNull("notified", alert.notifiedMs)
        val extras = posted.notification.extras
        assertEquals(context.getString(R.string.alert_review_title), extras.getCharSequence(Notification.EXTRA_TITLE)?.toString())
        assertEquals(context.getString(R.string.alert_review_text), extras.getCharSequence(Notification.EXTRA_TEXT)?.toString())
        assertNull("no severity", extras.getCharSequence(Notification.EXTRA_SUB_TEXT))
        val shown = listOf(Notification.EXTRA_TITLE, Notification.EXTRA_TEXT, Notification.EXTRA_BIG_TEXT)
            .joinToString(" ") { extras.getCharSequence(it)?.toString().orEmpty() }
        assertFalse(shown, shown.contains(spy))
        assertEquals(AlertNotifier.DISCREET_KEY, posted.tag)
        assertEquals(Notification.VISIBILITY_SECRET, posted.notification.visibility)
        assertTrue(AlertNotifier.isDiscreet(AlertRule.KNOWN_INDICATOR))
        assertFalse(AlertNotifier.isDiscreet(AlertRule.MONITORING_INTERRUPTED))
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
