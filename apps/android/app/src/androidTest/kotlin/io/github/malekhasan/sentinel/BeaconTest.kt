// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * DL-04 on a device (ADR-0031): which apps count as part of the system, whose regular
 * check-ins are not flagged. The pattern itself is found in the core, where the beacon
 * simulation runs.
 */
@RunWith(AndroidJUnit4::class)
class BeaconTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun appsThatCameWithThePhoneArePartOfTheSystem() {
        val names = AppNames(context)
        assertTrue("Android itself", names.isSystem(Process.SYSTEM_UID, "android"))
        val settings = "com.android.settings"
        @Suppress("DEPRECATION")
        val settingsUid = context.packageManager.getPackageUid(settings, 0)
        assertTrue("the Settings app", names.isSystem(settingsUid, settings))
        assertFalse("Sentinel, installed by the user", names.isSystem(Process.myUid(), context.packageName))
        assertFalse("an owner not known", names.isSystem(-1, null))
    }
}
