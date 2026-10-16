// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.hardware.camera2.CameraManager
import android.media.AudioManager
import android.media.AudioRecordingConfiguration
import android.os.Handler
import android.os.Looper
import android.util.Log
import io.github.malekhasan.sentinel.core.HistoryStore
import io.github.malekhasan.sentinel.core.SensorKind
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Microphone and camera use while monitoring runs (SE-01 basic, SE-03, SE-04, ADR-0027).
 *
 * Android tells an ordinary app when some app records audio or opens a camera, but not
 * which app (AM-15). Each use is recorded with the app on screen when it began, as a
 * guess, if the user granted usage access. While any sensor is in use, a notification
 * says so (SE-03). A use while the screen is off or locked raises a High alert (SE-04).
 *
 * The callbacks run on the main thread; the history is written in order on a thread of
 * its own.
 */
class SensorWatch(
    private val context: Context,
    private val history: HistoryStore,
    private val isAway: () -> Boolean,
) {
    private val main = Handler(Looper.getMainLooper())
    private val audio = context.getSystemService(AudioManager::class.java)
    private val cameras = context.getSystemService(CameraManager::class.java)
    private val notifications = context.getSystemService(NotificationManager::class.java)
    private val writes: ExecutorService = Executors.newSingleThreadExecutor { Thread(it, "sentinel-sensors") }

    // Main thread only.
    private var microphone = false
    private val camerasInUse = mutableSetOf<String>()

    // The writes thread only: the open use of each sensor, by id.
    private val open = mutableMapOf<SensorKind, Long>()

    private val recordings = object : AudioManager.AudioRecordingCallback() {
        override fun onRecordingConfigChanged(configs: List<AudioRecordingConfiguration>) =
            microphoneChanged(configs.isNotEmpty())
    }

    private val availability = object : CameraManager.AvailabilityCallback() {
        override fun onCameraUnavailable(cameraId: String) {
            val was = camerasInUse.isNotEmpty()
            camerasInUse += cameraId
            if (!was) changed(SensorKind.CAMERA, true)
        }

        override fun onCameraAvailable(cameraId: String) {
            val was = camerasInUse.isNotEmpty()
            camerasInUse -= cameraId
            if (was && camerasInUse.isEmpty()) changed(SensorKind.CAMERA, false)
        }
    }

    fun start() {
        createChannel(context)
        audio.registerAudioRecordingCallback(recordings, main)
        // Cameras in use now are reported to the callback at once; recordings are not.
        cameras.registerAvailabilityCallback(availability, main)
        microphoneChanged(audio.activeRecordingConfigurations.isNotEmpty())
    }

    fun stop() {
        audio.unregisterAudioRecordingCallback(recordings)
        cameras.unregisterAvailabilityCallback(availability)
        val now = System.currentTimeMillis()
        write {
            open.clear()
            history.endSensorUses(now)
        }
        writes.shutdown()
        notifications.cancel(NOTIFICATION_ID)
    }

    /** The screen went off or locked, or came back; called on the main thread. */
    fun awayChanged(away: Boolean) {
        if (away) write { open.values.forEach(history::sensorWhileAway) }
    }

    private fun microphoneChanged(inUse: Boolean) {
        if (inUse == microphone) return
        microphone = inUse
        changed(SensorKind.MICROPHONE, inUse)
    }

    private fun changed(sensor: SensorKind, inUse: Boolean) {
        val now = System.currentTimeMillis()
        // Shown at once (SE-03), before the history is written.
        showInUse()
        if (inUse) {
            val away = isAway()
            write {
                val guess = UsageAccess.foregroundApp(context)
                open[sensor] = history.sensorStarted(sensor, now, guess, !away)
            }
        } else {
            write { open.remove(sensor)?.let { history.sensorStopped(it, now) } }
        }
    }

    private fun showInUse() {
        val camera = camerasInUse.isNotEmpty()
        val title = when {
            microphone && camera -> R.string.sensors_in_use_both
            microphone -> R.string.sensors_in_use_microphone
            camera -> R.string.sensors_in_use_camera
            else -> {
                notifications.cancel(NOTIFICATION_ID)
                return
            }
        }
        val open = PendingIntent.getActivity(
            context,
            NOTIFICATION_ID,
            Intent(context, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_monitoring)
            .setContentTitle(context.getString(title))
            .setContentText(context.getString(R.string.sensors_in_use_text))
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
        try {
            notifications.notify(NOTIFICATION_ID, notification)
        } catch (e: SecurityException) {
            // Notifications not allowed: the use is still recorded.
            Log.w(TAG, "could not show that a sensor is in use", e)
        }
    }

    private fun write(work: () -> Unit) {
        if (writes.isShutdown) return
        writes.execute {
            try {
                work()
            } catch (e: Exception) {
                // HistoryException: the use goes unrecorded, monitoring goes on.
                Log.w(TAG, "could not record sensor use", e)
            }
        }
    }

    companion object {
        private const val TAG = "SentinelSensors"
        const val CHANNEL_ID = "sensors"
        const val NOTIFICATION_ID = 3

        /** A quiet channel: the notification shows while a sensor is in use, without a sound. */
        fun createChannel(context: Context) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.channel_sensors),
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = context.getString(R.string.channel_sensors_description) }
            context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }
}
