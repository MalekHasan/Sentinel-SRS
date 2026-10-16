// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import io.github.malekhasan.sentinel.core.trustedFeedKeys

/** The keys a release build trusts to sign the indicator feed: those of keys/feed (ADR-0019). */
object FeedKeys {
    val trusted: List<String> = trustedFeedKeys()
}
