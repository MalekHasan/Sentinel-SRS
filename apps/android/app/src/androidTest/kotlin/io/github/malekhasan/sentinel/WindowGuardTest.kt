// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.Build
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.View
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Audit A-17: Sentinel's windows, its dialogs' too, drop a touch made while another
 * app's window covers them, and on Android 14 are data-sensitive, so that accessibility
 * services that are not tools can neither read them nor press their buttons.
 */
@RunWith(AndroidJUnit4::class)
class WindowGuardTest {
    @get:Rule
    val compose = createEmptyComposeRule()

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test
    fun theMainScreenIsGuarded() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { assertGuarded(it.window.decorView) }
        }
    }

    /**
     * The question the notification's Stop opens is a dialog in a window of its own. A
     * tap on "Keep monitoring" that Android marks as made under another app's window does
     * nothing; the same tap unmarked answers it.
     */
    @Test
    fun aDialogDropsATouchMadeUnderAnotherWindow() {
        ActivityScenario.launch(StopMonitoringActivity::class.java).use {
            val keep = context.getString(R.string.stop_keep)
            fun asked() = try {
                compose.onAllNodesWithText(keep).fetchSemanticsNodes().isNotEmpty()
            } catch (e: IllegalStateException) {
                false // No Compose screen at all: the question is no longer open.
            }
            compose.waitUntil(10_000) { asked() }
            val button = compose.onNodeWithText(keep).fetchSemanticsNode()
            val window = (checkNotNull(button.root) as ViewRootForTest).view.rootView
            assertGuarded(window)
            val x = button.boundsInWindow.center.x
            val y = button.boundsInWindow.center.y

            tap(window, x, y, MotionEvent.FLAG_WINDOW_IS_OBSCURED)
            SystemClock.sleep(500)
            assertTrue("a touch under another window is dropped", asked())

            tap(window, x, y, 0)
            compose.waitUntil(10_000) { !asked() }
        }
    }

    private fun assertGuarded(window: View) {
        assertTrue("touches under another window are dropped", window.filterTouchesWhenObscured)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            assertTrue("hidden from accessibility services that are not tools", window.isAccessibilityDataSensitive)
        }
    }

    /** A finger's tap at [x], [y] in [window], with the [flags] Android sets on it. */
    private fun tap(window: View, x: Float, y: Float, flags: Int) {
        val properties = arrayOf(
            MotionEvent.PointerProperties().apply {
                id = 0
                toolType = MotionEvent.TOOL_TYPE_FINGER
            },
        )
        val coords = arrayOf(
            MotionEvent.PointerCoords().apply {
                this.x = x
                this.y = y
                pressure = 1f
                size = 1f
            },
        )
        val down = SystemClock.uptimeMillis()
        fun event(action: Int, at: Long) = MotionEvent.obtain(
            down, at, action, 1, properties, coords, 0, 0, 1f, 1f, 0, 0,
            InputDevice.SOURCE_TOUCHSCREEN, flags,
        )
        instrumentation.runOnMainSync {
            window.dispatchTouchEvent(event(MotionEvent.ACTION_DOWN, down))
            window.dispatchTouchEvent(event(MotionEvent.ACTION_UP, down + 50))
        }
    }
}
