// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.res.Configuration
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** The highest Flesch-Kincaid grade an alert text may have in English (AL-02). */
private const val MAX_GRADE = 8.0

/**
 * AL-02: what an alert says reads at grade 8 or lower in English, measured with the
 * Flesch-Kincaid grade formula. The formula is made for passages, not single words
 * ("Critical" alone scores 20), so it is applied to what is read together: each rule's
 * title and explanation, and the alert screen's other texts, each one sentence.
 * Placeholders count as one short word.
 */
@RunWith(AndroidJUnit4::class)
class AlertTextTest {
    private val english = InstrumentationRegistry.getInstrumentation().targetContext.let {
        val config = Configuration(it.resources.configuration)
        config.setLocale(Locale.ENGLISH)
        it.createConfigurationContext(config).resources
    }

    private val texts: Map<String, String> = R.string::class.java.fields
        .filter { it.name.startsWith("alert") || it.name.startsWith("severity_") }
        .associate { it.name to english.getString(it.getInt(null)) }

    @Test
    fun eachRulesTitleAndExplanationReadAtGradeEightOrLower() {
        val rules = texts.keys.filter { it.endsWith("_title") && texts.containsKey(it.replace("_title", "_text")) }
        assertTrue("rules found: $rules", rules.isNotEmpty())
        val grades = rules.associateWith { title ->
            grade(passage(listOf(texts.getValue(title), texts.getValue(title.replace("_title", "_text")))))
        }
        assertEquals("above grade $MAX_GRADE", emptyMap<String, Double>(), grades.filterValues { it > MAX_GRADE })
    }

    @Test
    fun theAlertScreensOtherTextsReadAtGradeEightOrLower() {
        val ruleTexts = texts.keys.filter { it.endsWith("_title") || it.endsWith("_text") }
            .filter { texts.containsKey(it.replace("_title", "_text")) && texts.containsKey(it.replace("_text", "_title")) }
        val others = (texts - ruleTexts.toSet()).values.toList()
        assertTrue("texts found: $others", others.size >= 10)
        val grade = grade(passage(others))
        assertTrue("grade $grade of: $others", grade <= MAX_GRADE)
    }

    /** Texts as one passage, each a sentence. */
    private fun passage(texts: List<String>): String = texts.joinToString(" ") { it.trimEnd('.') + "." }

    /** The formula, checked against hand-counted sentences. */
    @Test
    fun gradeFollowsTheFormula() {
        // 6 words, 1 sentence, 6 syllables: 0.39 * 6 + 11.8 * 1 - 15.59.
        assertEquals(-1.45, grade("The cat sat on the mat."), 0.01)
        assertEquals(4, syllables("monitoring"))
        assertEquals(1, syllables("stopped"))
        assertEquals(3, syllables("recorded"))
        assertEquals(1, syllables("time"))
    }

    private fun grade(text: String): Double {
        val plain = text.replace(Regex("%(\\d+\\$)?[sd]"), "it")
        val words = Regex("[A-Za-z']+").findAll(plain).map { it.value }.toList()
        if (words.isEmpty()) return 0.0
        val sentences = maxOf(1, Regex("[.!?]+").findAll(plain).count())
        val syllables = words.sumOf(::syllables)
        return 0.39 * words.size / sentences + 11.8 * syllables / words.size - 15.59
    }

    /** Vowel groups, less a silent final "e" and the silent "e" of "-ed" (not after t or d). */
    private fun syllables(word: String): Int {
        val w = word.lowercase().filter(Char::isLetter)
        var count = Regex("[aeiouy]+").findAll(w).count()
        if (count > 1 && w.endsWith("e") && !w.endsWith("le")) count--
        if (count > 1 && w.endsWith("ed") && w.length > 3 && w[w.length - 3] !in "td") count--
        return maxOf(1, count)
    }
}
