// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import io.github.malekhasan.sentinel.core.Engine
import io.github.malekhasan.sentinel.core.EngineSnapshot
import io.github.malekhasan.sentinel.core.Feed
import io.github.malekhasan.sentinel.core.FlowRecord
import io.github.malekhasan.sentinel.core.IpSources
import io.github.malekhasan.sentinel.core.LiveApp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Monitoring state for the whole process, shared by [SentinelVpnService] and the UI. */
object Monitor {
    enum class Status { OFF, STARTING, ON }

    private val mutableStatus = MutableStateFlow(Status.OFF)
    val status: StateFlow<Status> = mutableStatus.asStateFlow()

    @Volatile
    private var engine: Engine? = null

    /** Flows of the current session by id, oldest first, bounded: the live view. The
     *  durable record is the encrypted [History]. */
    private val flows = object : LinkedHashMap<ULong, FlowRecord>() {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<ULong, FlowRecord>?) =
            size > RECENT_FLOWS
    }

    internal fun starting() {
        // Flow ids start again at 1 with every engine.
        synchronized(flows) { flows.clear() }
        mutableStatus.value = Status.STARTING
    }

    /** New and finished flows from the engine (called on an engine thread). */
    internal fun flowsUpdated(records: List<FlowRecord>) {
        synchronized(flows) { records.forEach { flows[it.id] = it } }
    }

    /** The most recent flows of this session, newest first. */
    fun recentFlows(): List<FlowRecord> = synchronized(flows) { flows.values.reversed() }

    internal fun started(engine: Engine) {
        this.engine = engine
        mutableStatus.value = Status.ON
    }

    internal fun stopped() {
        engine = null
        alwaysOn = null
        ipSources = null
        trackerSources = null
        matchesIndicators = false
        mutableStatus.value = Status.OFF
    }

    /** Whether Sentinel is the always-on VPN, as the running service last saw; null when off. */
    @Volatile
    var alwaysOn: Boolean? = null
        internal set

    /** The sources of the IP database the engine uses, or null while it has none. */
    @Volatile
    var ipSources: IpSources? = null
        private set

    internal fun ipDataLoaded(sources: IpSources) {
        ipSources = sources
    }

    /** The lists the engine's tracker list was built from, or null while it has none. */
    @Volatile
    var trackerSources: List<String>? = null
        private set

    internal fun trackerDataLoaded(sources: List<String>) {
        trackerSources = sources
    }

    /** Whether the engine matches traffic against the indicator feed (ID-13). */
    @Volatile
    var matchesIndicators: Boolean = false
        private set

    internal fun feedSet(feed: Feed?) {
        matchesIndicators = feed != null
    }

    private const val RECENT_FLOWS = 500

    /** Live engine counters, or null when monitoring is off. */
    fun snapshot(): EngineSnapshot? = engine?.let { runCatching { it.snapshot() }.getOrNull() }

    /** Open connections grouped by app, busiest first (CM-03); empty when monitoring is
     *  off. */
    fun liveApps(): List<LiveApp> =
        engine?.let { runCatching { it.liveApps() }.getOrNull() }.orEmpty()
}
