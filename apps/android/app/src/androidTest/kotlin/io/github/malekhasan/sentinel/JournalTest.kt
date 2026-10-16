// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.malekhasan.sentinel.core.FirewallMode
import io.github.malekhasan.sentinel.core.FirewallRule
import io.github.malekhasan.sentinel.core.HistoryStore
import io.github.malekhasan.sentinel.core.JournalEntry
import io.github.malekhasan.sentinel.core.JournalState
import io.github.malekhasan.sentinel.core.RuleAction
import io.github.malekhasan.sentinel.core.RuleDestination
import java.text.DateFormat
import java.util.Date
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * SRS §9 on a device (ADR-0018): each change the user makes to the firewall is in the
 * journal, which says what it did and undoes it with one tap, at once.
 */
@RunWith(AndroidJUnit4::class)
class JournalTest {
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val undo = context.getString(R.string.journal_undo)
    private lateinit var history: HistoryStore

    @Before
    fun setUp() {
        grantMonitoringPermissions()
        History.wipe(context)
        history = History.get(context)
    }

    @After
    fun tearDown() {
        stopMonitoring()
        endIsolation(context)
        history.setFirewallMode(FirewallMode.MONITOR)
        history.firewallRules().forEach { history.removeFirewallRule(it.key) }
    }

    /** RA-01 undone: blocking this app from an alert, then Undo, gives it the internet back. */
    @Test
    fun undoingABlockFromAnAlertLetsTheAppBackIn() {
        history.openGap(null, "test")
        val alert = history.alerts(true, 10u).first().id
        startMonitoring()
        val (host, port) = testServer()
        assertNotNull("reachable before", answer(host, port))
        assertTrue(blockApp(context, context.packageName, alert))
        assertNull("blocked", answer(host, port))
        val entry = history.journal(10u).single()
        assertEquals("taken from the alert", alert, entry.alertId)
        assertTrue(entry.canUndo)

        compose.setContent { SentinelTheme { JournalScreen(onBack = {}) } }
        val label = AppNames(context).labelFor(context.packageName)
        waitUntilShown(context.getString(R.string.journal_block_app, isolate(label)))
        compose.onNodeWithText(context.getString(R.string.journal_from_alert)).assertIsDisplayed()
        tapUndo(entry.id)
        waitUntilShown(context.getString(R.string.journal_undo_done))
        waitFor("the block undone") { history.appAccess(context.packageName, null).rule == null }
        assertNotNull("reachable again", answer(host, port))
        compose.waitUntil(5_000) { compose.onAllNodes(undoIn(entry.id)).fetchSemanticsNodes().isEmpty() }
        assertNotNull("says when it was undone", history.journal(10u).single().undoneMs)
    }

    /** RA-03 and CM-08 undone from the journal, newest first; isolation keeps when it began. */
    @Test
    fun isolationAndTheModeAreUndoneNewestFirst() {
        assertTrue(setFirewallMode(context, FirewallMode.BLOCK_UNKNOWN))
        assertTrue(isolatePhone(context))
        val began = checkNotNull(history.isolatedSinceMs())
        assertTrue(endIsolation(context))

        val (ended, isolated, switched) = history.journal(10u).map { it.id }
        compose.setContent { SentinelTheme { JournalScreen(onBack = {}) } }
        waitUntilShown(context.getString(R.string.journal_isolation_ended))
        // Isolating can be undone only once ending it was: until then, nothing to undo.
        compose.onAllNodes(undoIn(isolated)).assertCountEquals(0)
        tapUndo(ended)
        waitFor("isolated again") { history.isolatedSinceMs() == began }
        tapUndo(isolated)
        waitFor("isolation undone") { history.isolatedSinceMs() == null }
        tapUndo(switched)
        waitFor("the mode undone") { history.firewallMode() == FirewallMode.MONITOR }
        compose.waitUntil(5_000) { compose.onAllNodesWithText(undo).fetchSemanticsNodes().isEmpty() }
    }

    /** Each kind of action in one sentence, with when, where it came from and Undo. */
    @Test
    fun theJournalSaysWhatEachActionDid() {
        val app = "org.example.chat"
        val now = System.currentTimeMillis()
        val blockChat = FirewallRule(app, null, RuleAction.BLOCK)
        val allowAds = FirewallRule(app, RuleDestination.Domain("ads.example"), RuleAction.ALLOW)
        val blockCompany = FirewallRule(null, RuleDestination.Company("Example Ads"), RuleAction.BLOCK)
        fun entry(
            id: Long,
            before: JournalState,
            after: JournalState,
            canUndo: Boolean,
            alertId: Long? = null,
            undoneMs: Long? = null,
        ) = JournalEntry(id, now, alertId, before, after, undoneMs, canUndo)
        fun rule(rule: FirewallRule?, key: String) = JournalState.Rule(key, rule)
        val rows = listOf(
            JournalRow(entry(5, rule(null, "a"), rule(blockChat, "a"), canUndo = true, alertId = 1), "Chat"),
            JournalRow(entry(4, rule(null, "b"), rule(allowAds, "b"), canUndo = false, undoneMs = now), "Chat"),
            JournalRow(entry(3, rule(blockCompany, "c"), rule(null, "c"), canUndo = false), null),
            JournalRow(
                entry(
                    2,
                    JournalState.Mode(FirewallMode.MONITOR, null),
                    JournalState.Mode(FirewallMode.BLOCK_UNKNOWN, now),
                    canUndo = true,
                ),
                null,
            ),
            JournalRow(entry(1, JournalState.Isolation(now), JournalState.Isolation(null), canUndo = false), null),
        )
        val undone = mutableListOf<Long>()
        compose.setContent { SentinelTheme { Journal(rows, onBack = {}, onUndo = { undone += it }) } }

        val format = DateFormat.getDateTimeInstance(
            DateFormat.SHORT, DateFormat.SHORT, context.resources.configuration.locales[0],
        )
        for (text in listOf(
            context.getString(R.string.journal_title),
            context.getString(R.string.journal_block_app, isolate("Chat")),
            context.getString(R.string.journal_from_alert),
            context.getString(R.string.journal_allow_for_app, isolate("ads.example"), isolate("Chat")),
            context.getString(R.string.journal_undone, format.format(Date(now))),
            context.getString(
                R.string.journal_rule_removed,
                context.getString(
                    R.string.journal_block_everywhere,
                    context.getString(R.string.journal_company, isolate("Example Ads")),
                ),
            ),
            context.getString(R.string.journal_mode, context.getString(R.string.firewall_mode_block_unknown)),
            context.getString(R.string.journal_isolation_ended),
        )) {
            compose.onNodeWithTag(JOURNAL_LIST_TAG).performScrollToNode(hasText(text))
            compose.onNodeWithText(text).assertIsDisplayed()
        }
        // Undo only where it would put back what was there: not after an undo, and not
        // once something changed the setting again.
        for (id in 5L downTo 1L) {
            compose.onNodeWithTag(JOURNAL_LIST_TAG).performScrollToNode(hasTestTag(journalRowTag(id)))
            compose.onAllNodes(undoIn(id)).assertCountEquals(if (id == 5L || id == 2L) 1 else 0)
        }
        tapUndo(5)
        assertEquals(listOf(5L), undone)
    }

    /** The Undo button of action [id]. */
    private fun undoIn(id: Long) = hasText(undo) and hasAnyAncestor(hasTestTag(journalRowTag(id)))

    /** Taps action [id]'s Undo once it is shown. */
    private fun tapUndo(id: Long) {
        compose.onNodeWithTag(JOURNAL_LIST_TAG).performScrollToNode(hasTestTag(journalRowTag(id)))
        compose.waitUntil(5_000) { compose.onAllNodes(undoIn(id)).fetchSemanticsNodes().isNotEmpty() }
        compose.onNode(undoIn(id)).performClick()
    }

    private fun waitUntilShown(text: String) {
        compose.waitUntil(5_000) { compose.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty() }
    }
}
