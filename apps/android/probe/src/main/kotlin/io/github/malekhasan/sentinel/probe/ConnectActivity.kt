// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel.probe

import android.app.Activity
import android.os.Bundle
import android.util.Log
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Opens one TCP connection to the `host` and `port` it is started with, sends an HTTP
 * request, reads the answer, and finishes. The device tests read what Sentinel recorded
 * about the connection; the log says what this side saw.
 */
class ConnectActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val host = intent.getStringExtra(EXTRA_HOST)
        val port = intent.getIntExtra(EXTRA_PORT, -1)
        if (host == null || port !in 1..65535) {
            Log.w(TAG, "start me with --es $EXTRA_HOST <address> --ei $EXTRA_PORT <port>")
            finish()
            return
        }
        Thread({
            val result = try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(host, port), TIMEOUT_MS)
                    socket.soTimeout = TIMEOUT_MS
                    socket.getOutputStream().write("GET / HTTP/1.0\r\n\r\n".toByteArray())
                    "answered with ${socket.getInputStream().readBytes().size} bytes"
                }
            } catch (e: IOException) {
                "failed: $e"
            }
            Log.i(TAG, "$host:$port $result")
            runOnUiThread { finish() }
        }, "probe-connect").start()
    }

    private companion object {
        const val TAG = "SentinelProbe"
        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val TIMEOUT_MS = 5_000
    }
}
