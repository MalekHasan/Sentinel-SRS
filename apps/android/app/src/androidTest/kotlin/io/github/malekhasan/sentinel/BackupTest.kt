// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.pm.ApplicationInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.xmlpull.v1.XmlPullParser

/**
 * NF-11 (THREAT-MODEL-A I2, audit A-46): nothing of Sentinel's leaves the phone, by cloud
 * backup or by moving to a new phone. Backup is off, and the rules the manifest names for
 * Android 12+ exclude every domain from both and include none.
 */
@RunWith(AndroidJUnit4::class)
class BackupTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun nothingIsBackedUpOrMovedToAnotherPhone() {
        assertEquals("backup is off", 0, context.applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP)

        val excluded = mutableMapOf<String, MutableSet<String>>()
        var section: String? = null
        val parser = context.resources.getXml(R.xml.data_extraction_rules)
        try {
            while (parser.next() != XmlPullParser.END_DOCUMENT) {
                if (parser.eventType != XmlPullParser.START_TAG) continue
                val domain = parser.getAttributeValue(null, "domain")
                when (parser.name) {
                    "cloud-backup", "device-transfer" -> section = parser.name
                    "include" -> fail("$section includes $domain")
                    "exclude" -> {
                        assertEquals("all of $domain", ".", parser.getAttributeValue(null, "path"))
                        excluded.getOrPut(checkNotNull(section)) { mutableSetOf() } += domain
                    }
                }
            }
        } finally {
            parser.close()
        }
        val every = setOf(
            "root", "file", "database", "sharedpref", "external",
            "device_root", "device_file", "device_database", "device_sharedpref",
        )
        assertEquals(mapOf("cloud-backup" to every, "device-transfer" to every), excluded)
    }
}
