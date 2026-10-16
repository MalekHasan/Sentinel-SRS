// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.res.Configuration
import android.content.res.Resources
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Strings that are a name and nothing else. */
private val NAMES = setOf("app_name")

/** Format placeholders. The code wraps the values it puts there in [isolate]. */
private val PLACEHOLDER = Regex("%(\\d+\\$)?[sd]")

/**
 * Every string reads in its language's direction (S3.4). Android lays a line out in the
 * direction of its first letter, so an Arabic sentence that starts with a Latin word
 * (for example the app's name) is laid out left to right, with its words in the wrong
 * order. Plurals are checked in every form Arabic has.
 */
@RunWith(AndroidJUnit4::class)
class StringsTest {
    private val base = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun arabicStringsStartRightToLeft() {
        assertEquals("strings that start left to right", emptyList<String>(), wrongDirection("ar", rtl = true))
    }

    @Test
    fun englishStringsStartLeftToRight() {
        assertEquals("strings that start right to left", emptyList<String>(), wrongDirection("en", rtl = false))
    }

    /** MS-15: no text calls the phone or a result clean or safe, in either language. */
    @Test
    fun noTextSaysCleanOrSafe() {
        val banned = mapOf(
            "en" to Regex("\\b(clean|safe)\\b", RegexOption.IGNORE_CASE),
            "ar" to Regex("نظيف|آمن"),
        )
        val found = banned.flatMap { (language, words) ->
            texts(resources(language))
                .filter { (_, text) -> words.containsMatchIn(text) }
                .map { (name, text) -> "$language $name: $text" }
        }
        assertEquals(emptyList<String>(), found)
    }

    private fun wrongDirection(language: String, rtl: Boolean): List<String> =
        texts(resources(language)).filter { (_, text) -> startsRightToLeft(text) == !rtl }
            .map { (name, text) -> "$name: $text" }

    private fun resources(language: String): Resources {
        val config = Configuration(base.resources.configuration)
        config.setLocale(Locale.forLanguageTag(language))
        return base.createConfigurationContext(config).resources
    }

    /** This app's strings, and its plurals for the counts that pick each Arabic form. */
    private fun texts(resources: Resources): List<Pair<String, String>> {
        val strings = R.string::class.java.fields
            .filter { it.name !in NAMES }
            .map { it.name to resources.getString(it.getInt(null)) }
        val plurals = R.plurals::class.java.fields.flatMap { field ->
            listOf(0, 1, 2, 3, 11, 100).map { count ->
                "${field.name}[$count]" to resources.getQuantityString(field.getInt(null), count)
            }
        }
        return strings + plurals
    }

    /** The direction of the first letter outside placeholders, or null if there is none. */
    private fun startsRightToLeft(text: String): Boolean? {
        val bare = PLACEHOLDER.replace(text, "")
        var index = 0
        while (index < bare.length) {
            val codePoint = bare.codePointAt(index)
            when (Character.getDirectionality(codePoint)) {
                Character.DIRECTIONALITY_LEFT_TO_RIGHT -> return false
                Character.DIRECTIONALITY_RIGHT_TO_LEFT,
                Character.DIRECTIONALITY_RIGHT_TO_LEFT_ARABIC -> return true
            }
            index += Character.charCount(codePoint)
        }
        return null
    }
}
