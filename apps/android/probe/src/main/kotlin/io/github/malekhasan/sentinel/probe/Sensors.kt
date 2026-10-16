// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel.probe

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log

// The device tests' microphone and camera user (SE-01, SE-04): each activity uses its
// sensor for `seconds` seconds, logs what it did, and finishes. The tests grant the
// permissions with `pm grant`.

private const val TAG = "SentinelProbe"
private const val EXTRA_SECONDS = "seconds"

/** Records from the microphone, keeping nothing. */
class RecordActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val seconds = intent.getIntExtra(EXTRA_SECONDS, 3)
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            Log.w(TAG, "record: no permission")
            finish()
            return
        }
        Thread({ record(seconds) }, "probe-record").start()
    }

    private fun record(seconds: Int) {
        val rate = 16_000
        val size = AudioRecord.getMinBufferSize(rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val recorder = try {
            AudioRecord(
                MediaRecorder.AudioSource.MIC, rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, size * 2,
            )
        } catch (e: SecurityException) {
            Log.w(TAG, "record: no permission", e)
            runOnUiThread { finish() }
            return
        }
        if (recorder.state != AudioRecord.STATE_INITIALIZED) {
            Log.w(TAG, "record: no microphone")
            recorder.release()
            runOnUiThread { finish() }
            return
        }
        recorder.startRecording()
        Log.i(TAG, "record: started")
        val buffer = ShortArray(size)
        val end = SystemClock.elapsedRealtime() + seconds * 1_000L
        while (SystemClock.elapsedRealtime() < end) recorder.read(buffer, 0, buffer.size)
        recorder.stop()
        recorder.release()
        Log.i(TAG, "record: stopped")
        runOnUiThread { finish() }
    }
}

/** Opens the first camera and closes it again. */
class CameraActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val seconds = intent.getIntExtra(EXTRA_SECONDS, 3)
        val cameras = getSystemService(CameraManager::class.java)
        val camera = cameras.cameraIdList.firstOrNull()
        if (camera == null || checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            Log.w(TAG, "camera: none, or no permission")
            finish()
            return
        }
        val main = Handler(Looper.getMainLooper())
        val callback = object : CameraDevice.StateCallback() {
            override fun onOpened(device: CameraDevice) {
                Log.i(TAG, "camera: opened")
                main.postDelayed({
                    device.close()
                    Log.i(TAG, "camera: closed")
                    finish()
                }, seconds * 1_000L)
            }

            override fun onDisconnected(device: CameraDevice) {
                device.close()
                finish()
            }

            override fun onError(device: CameraDevice, error: Int) {
                Log.w(TAG, "camera: error $error")
                device.close()
                finish()
            }
        }
        try {
            cameras.openCamera(camera, callback, main)
        } catch (e: SecurityException) {
            Log.w(TAG, "camera: no permission", e)
            finish()
        }
    }
}
