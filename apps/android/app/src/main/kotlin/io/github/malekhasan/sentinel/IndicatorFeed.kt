// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import io.github.malekhasan.sentinel.core.Feed
import io.github.malekhasan.sentinel.core.FeedFailure
import io.github.malekhasan.sentinel.core.FeedOffer
import io.github.malekhasan.sentinel.core.FeedStatus
import io.github.malekhasan.sentinel.core.trustedFeedThreshold
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The signed indicator feed on this phone (SRS MS-10, SP-04; ADR-0019). The core decides
 * what may be fetched and what comes into force; this object fetches, over HTTPS from
 * where the feed is published or from a folder the user picks, and tells the screens.
 *
 * All of it reads or writes files, and some of it the network: call it off the main
 * thread.
 */
object IndicatorFeed {
    private const val TAG = "SentinelFeed"

    /** Where the newest bundle is published: its files, next to its manifest. */
    const val PUBLISHED = "https://github.com/MalekHasan/Sentinel-SRS/releases/download/feed/"

    /** How often to look for a newer list: weekly lists, urgent ones the same day (MS-10). */
    const val CHECK_EVERY_MILLIS = 6 * 60 * 60 * 1000L

    /** How often to check the list in force again (SP-04). */
    const val RECHECK_EVERY_MILLIS = 60 * 60 * 1000L

    private const val MANIFEST = "manifest.dsse.json"
    private const val MAX_MANIFEST_BYTES = 1L shl 20
    private const val PREFS = "feed"
    private const val LAST_CHECK = "last_check"

    /** What the last check or update found. */
    enum class Outcome {
        INSTALLED,
        UP_TO_DATE,
        /** Signature, version, expiry, a file's hash or an indicator's provenance failed. */
        REFUSED,
        /** The place holds no list. */
        NOT_FOUND,
        /** A file the list names is missing there. */
        INCOMPLETE,
        UNREACHABLE,
        /** The list could not be written on this phone. */
        FAILED,
        /** The list in force failed its check again and was removed. */
        REMOVED,
    }

    /** What the screens show about the feed. */
    data class State(
        /** False when this build has no keys to check a list with. */
        val available: Boolean = true,
        /** The list in force, as last checked. */
        val status: FeedStatus? = null,
        val busy: Boolean = false,
        val last: Outcome? = null,
    )

    private val state = MutableStateFlow(State())
    val states: StateFlow<State> = state.asStateFlow()

    private var opened = false
    private var feed: Feed? = null
    // Held while a list is fetched, which may take a while; [get] does not wait for it.
    private val updating = Any()
    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    /** Where the bundles live. Not backed up: the feed is downloaded again. */
    fun dir(context: Context): File = File(context.noBackupFilesDir, "feed")

    /** Next to [dir], so that installing moves files rather than copying them. */
    private fun staging(context: Context): File = File(context.noBackupFilesDir, "feed-staging")

    /**
     * The feed, its list in force checked when first opened (SP-04), or null when this
     * build has no keys to check lists with.
     */
    @Synchronized
    fun get(context: Context): Feed? {
        if (!opened) {
            opened = true
            feed = try {
                Feed.open(dir(context).path, FeedKeys.trusted, trustedFeedThreshold())
            } catch (e: FeedFailure) {
                Log.w(TAG, "no keys to check indicator lists with", e)
                null
            }
            val opened = feed
            if (opened == null) state.value = State(available = false) else recheck(opened)
        }
        return feed
    }

    /** The path of file [name] of the list in force, if it has one. */
    fun file(context: Context, name: String): File? = get(context)?.file(name)?.let(::File)

    /** Check the list in force again (SP-04). A list that fails is removed. */
    fun recheck(context: Context) {
        get(context)?.let(::recheck)
    }

    /** Told after a list comes into force or is removed, on the thread that did it. */
    fun addListener(listener: () -> Unit) {
        listeners += listener
    }

    fun removeListener(listener: () -> Unit) {
        listeners -= listener
    }

    /** Whether the last look for a new list was long enough ago to look again. */
    fun checkDue(context: Context): Boolean {
        val last = prefs(context).getLong(LAST_CHECK, 0)
        val now = System.currentTimeMillis()
        return now - last >= CHECK_EVERY_MILLIS || now < last
    }

    /** Look for a newer list where the feed is published, and install it. */
    fun checkPublished(context: Context): Outcome {
        val outcome = update(context, HttpSource(PUBLISHED))
        if (outcome != Outcome.UNREACHABLE) {
            prefs(context).edit().putLong(LAST_CHECK, System.currentTimeMillis()).apply()
        }
        return outcome
    }

    /** Install the list in the folder [tree] the user picked, if it is newer. */
    fun importFrom(context: Context, tree: Uri): Outcome = update(context, TreeSource(context, tree))

    /**
     * Fetch the list [source] offers and install it, if it is newer than the one in force
     * and passes every check. The history (MS-02) and the installed apps (ID-13) are then
     * checked against a list installed, before this returns.
     */
    fun update(context: Context, source: BundleSource): Outcome {
        val feed = get(context) ?: return Outcome.FAILED
        val outcome = synchronized(updating) {
            state.value = state.value.copy(busy = true)
            val fetched = fetch(feed, source, staging(context))
            state.value = state.value.copy(busy = false, status = feed.status(), last = fetched)
            if (fetched == Outcome.INSTALLED) listeners.forEach { it() }
            fetched
        }
        if (outcome == Outcome.INSTALLED) {
            History.hunt(context)
            InstalledApps.check(context)
        }
        return outcome
    }

    private fun recheck(feed: Feed) {
        val removed = try {
            feed.recheck()
            false
        } catch (e: FeedFailure) {
            Log.w(TAG, "the indicator list in force failed its check and was removed", e)
            true
        }
        state.value = state.value.copy(
            status = feed.status(),
            last = if (removed) Outcome.REMOVED else state.value.last,
        )
        if (removed) listeners.forEach { it() }
    }

    private fun fetch(feed: Feed, source: BundleSource, staging: File): Outcome {
        staging.deleteRecursively()
        return try {
            val manifest = source.open(MANIFEST)?.use { it.readAtMost(MAX_MANIFEST_BYTES) }
                ?: return Outcome.NOT_FOUND
            when (val offer = feed.offer(manifest)) {
                FeedOffer.UpToDate -> Outcome.UP_TO_DATE
                is FeedOffer.Update -> {
                    if (!staging.mkdirs()) return Outcome.FAILED
                    File(staging, MANIFEST).writeBytes(manifest)
                    for (file in offer.files) {
                        val target = File(staging, file.path)
                        target.parentFile?.mkdirs()
                        val input = source.open(file.path) ?: return Outcome.INCOMPLETE
                        input.use { it.copyAtMost(target, file.size.toLong()) }
                    }
                    feed.install(staging.path)
                    Outcome.INSTALLED
                }
            }
        } catch (e: FeedFailure.Refused) {
            Log.w(TAG, "an indicator list was refused", e)
            Outcome.REFUSED
        } catch (e: LargerThanListed) {
            Log.w(TAG, "an indicator list was refused", e)
            Outcome.REFUSED
        } catch (e: FeedFailure) {
            Log.w(TAG, "an indicator list could not be stored", e)
            Outcome.FAILED
        } catch (e: IOException) {
            Log.w(TAG, "an indicator list could not be fetched", e)
            Outcome.UNREACHABLE
        } finally {
            staging.deleteRecursively()
        }
    }

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Where a bundle's files are fetched from. */
    fun interface BundleSource {
        /** File [path] of the bundle, or null if there is no such file. */
        @Throws(IOException::class)
        fun open(path: String): InputStream?
    }

    /**
     * Over HTTPS from [base]. Release builds refuse plain HTTP (Android's default for
     * apps); the request carries nothing about the user or the phone.
     */
    class HttpSource(private val base: String) : BundleSource {
        override fun open(path: String): InputStream? {
            val url = URL(base + path.split('/').joinToString("/") { Uri.encode(it) })
            val connection = url.openConnection() as HttpURLConnection
            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            connection.useCaches = false
            // Android's default names the phone's model.
            connection.setRequestProperty("User-Agent", "Sentinel")
            return when (val code = connection.responseCode) {
                HttpURLConnection.HTTP_OK -> connection.inputStream
                HttpURLConnection.HTTP_NOT_FOUND -> {
                    connection.disconnect()
                    null
                }
                else -> {
                    connection.disconnect()
                    throw IOException("HTTP $code for $path")
                }
            }
        }
    }

    /** From a folder the user picked; the bundle's files must be directly in it. */
    class TreeSource(private val context: Context, private val tree: Uri) : BundleSource {
        private val children: Map<String, Uri> by lazy {
            try {
                list()
            } catch (e: RuntimeException) {
                // The folder went away, or the permission to read it.
                Log.w(TAG, "the folder cannot be read", e)
                emptyMap()
            }
        }

        private fun list(): Map<String, Uri> {
            val resolver = context.contentResolver
            val parent = DocumentsContract.buildChildDocumentsUriUsingTree(
                tree, DocumentsContract.getTreeDocumentId(tree),
            )
            val found = mutableMapOf<String, Uri>()
            resolver.query(
                parent,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                ),
                null, null, null,
            )?.use { rows ->
                while (rows.moveToNext()) {
                    val id = rows.getString(0) ?: continue
                    val name = rows.getString(1) ?: continue
                    found[name] = DocumentsContract.buildDocumentUriUsingTree(tree, id)
                }
            }
            return found
        }

        override fun open(path: String): InputStream? =
            children[path]?.let { context.contentResolver.openInputStream(it) }
    }

    /** A file is larger than its manifest says. */
    private class LargerThanListed(message: String) : IOException(message)

    private fun InputStream.readAtMost(limit: Long): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        copyAtMost(out, limit, "the manifest")
        return out.toByteArray()
    }

    private fun InputStream.copyAtMost(target: File, limit: Long) {
        target.outputStream().use { copyAtMost(it, limit, target.name) }
    }

    /** Copy at most [limit] bytes to [out]; more is refused, as a file larger than listed. */
    private fun InputStream.copyAtMost(out: java.io.OutputStream, limit: Long, what: String) {
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val read = read(buffer)
            if (read < 0) break
            total += read
            if (total > limit) throw LargerThanListed("$what is larger than listed")
            out.write(buffer, 0, read)
        }
    }
}
