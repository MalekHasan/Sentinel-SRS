// SPDX-License-Identifier: GPL-3.0-or-later
// Written by apps/android/scripts/make-test-feed.sh.
package io.github.malekhasan.sentinel

import io.github.malekhasan.sentinel.core.trustedFeedKeys

/**
 * The keys a debug build trusts to sign the indicator feed: those of keys/feed, and the
 * key that signed the device tests' bundles (ADR-0019). Its secret key was deleted once
 * they were signed. Release builds trust keys/feed only.
 */
object FeedKeys {
    private const val TEST_KEY = "8eda9dba4d5f752c16ee3ad279d01f52ee44b09c05a783a63783fd2aca95d2ff"

    val trusted: List<String> = trustedFeedKeys() + TEST_KEY
}
