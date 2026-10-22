// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

/**
 * Wraps a value that goes into a translated sentence (an app name, a hostname, an
 * address) in Unicode "first strong isolate" marks, so that it keeps its own direction
 * and does not set the sentence's. Without them, an Arabic sentence that starts with a
 * Latin package name is laid out left to right, and the parts around it are reordered.
 *
 * The value's own direction controls are dropped (audit A-43). Any app chooses its name,
 * and one holding an isolate's end (U+2069) could leave the isolate and, with an override
 * (U+202E), turn the rest of the sentence around; within the isolate, an override could
 * show the name backwards. No name, address or hostname needs them.
 */
fun isolate(text: String): String = "\u2068${text.filterNot { it in DIRECTION_CONTROLS }}\u2069"

/**
 * Unicode's explicit direction controls: the marks (U+061C, U+200E, U+200F), embeddings
 * and overrides (U+202A to U+202E) and isolates (U+2066 to U+2069).
 */
private val DIRECTION_CONTROLS = setOf(
    '\u061C', '\u200E', '\u200F',
    '\u202A', '\u202B', '\u202C', '\u202D', '\u202E',
    '\u2066', '\u2067', '\u2068', '\u2069',
)

/** A destination and its port as one unit; IPv6 addresses go in brackets. */
fun hostAndPort(host: String, port: Int): String =
    if (':' in host) "[$host]:$port" else "$host:$port"
