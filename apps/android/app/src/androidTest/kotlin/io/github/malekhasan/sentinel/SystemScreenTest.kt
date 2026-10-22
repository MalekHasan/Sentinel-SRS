// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.provider.Settings
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Audit A-40: Android's screens open in apps that came with the phone, never in another
 * app that claims their names. Debug builds claim the Settings app's trusted
 * certificates for this test, as spyware could.
 */
@RunWith(AndroidJUnit4::class)
class SystemScreenTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun androidsScreensOpenOnlyInAppsThatCameWithThePhone() {
        val certificates = Intent(Posture.TRUSTED_CREDENTIALS_USER)
        @Suppress("DEPRECATION")
        val claimers = context.packageManager
            .queryIntentActivities(certificates, PackageManager.MATCH_DEFAULT_ONLY)
            .map { it.activityInfo.packageName }
        assertTrue("the claim is there to be taken: $claimers", context.packageName in claimers)

        // The certificates screen may be missing from a phone's Settings; the others are not.
        assertOfThePhone(context.systemScreen(certificates))
        assertOfThePhone(checkNotNull(context.systemScreen(Intent(Settings.ACTION_SECURITY_SETTINGS))))
        assertOfThePhone(checkNotNull(context.systemScreen(Intent(Settings.ACTION_SETTINGS))))
        assertNull(context.systemScreen(Intent("org.example.NO_SUCH_SCREEN")))
    }

    /** That [screen], if any, opens in an app that came with the phone, and not in Sentinel. */
    private fun assertOfThePhone(screen: Intent?) {
        val app = screen?.component?.packageName ?: return
        assertNotEquals(context.packageName, app)
        @Suppress("DEPRECATION")
        val flags = context.packageManager.getApplicationInfo(app, 0).flags
        assertTrue("$app came with the phone", (flags and ApplicationInfo.FLAG_SYSTEM) != 0)
    }
}
