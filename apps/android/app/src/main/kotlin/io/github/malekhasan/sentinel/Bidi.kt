// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

/**
 * Wraps a value that goes into a translated sentence (an app name, a hostname, an
 * address) in Unicode "first strong isolate" marks, so that it keeps its own direction
 * and does not set the sentence's. Without them, an Arabic sentence that starts with a
 * Latin package name is laid out left to right, and the parts around it are reordered.
 */
fun isolate(text: String): String = "\u2068$text\u2069"

/** A destination and its port as one unit; IPv6 addresses go in brackets. */
fun hostAndPort(host: String, port: Int): String =
    if (':' in host) "[$host]:$port" else "$host:$port"
