// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import io.github.malekhasan.sentinel.core.Engine
import io.github.malekhasan.sentinel.core.EngineSnapshot
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

    internal fun starting() {
        mutableStatus.value = Status.STARTING
    }

    internal fun started(engine: Engine) {
        this.engine = engine
        mutableStatus.value = Status.ON
    }

    internal fun stopped() {
        engine = null
        mutableStatus.value = Status.OFF
    }

    /** Live engine counters, or null when monitoring is off. */
    fun snapshot(): EngineSnapshot? = engine?.let { runCatching { it.snapshot() }.getOrNull() }
}
