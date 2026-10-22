// SPDX-License-Identifier: GPL-3.0-or-later
package io.github.malekhasan.sentinel

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The key of the history database (ADR-0009): 32 random bytes, stored only encrypted
 * with an AES-GCM key that lives in the Android Keystore and cannot be exported.
 */
object HistoryKey {
    private const val ALIAS = "sentinel-history-key"
    private const val FILE = "history.key"
    /** As the history database set aside with it (sentinel-store `SET_ASIDE`). */
    private const val SET_ASIDE = ".unreadable"
    private const val KEY_BYTES = 32
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    /**
     * The stored key can never be read: the Keystore key that wraps it is gone, or it
     * fails its check (audit A-06). Any other failure to read it may pass, and is thrown
     * as it is.
     */
    class Lost(message: String, cause: Throwable? = null) : Exception(message, cause)

    /**
     * The key, created on first use. The caller should clear it after use. Throws [Lost]
     * when the stored key can never be read.
     */
    fun load(context: Context): ByteArray {
        val file = file(context)
        if (file.exists()) return unwrap(file.readBytes())
        val key = ByteArray(KEY_BYTES).also { SecureRandom().nextBytes(it) }
        val tmp = File(file.path + ".tmp")
        tmp.writeBytes(wrap(key))
        check(tmp.renameTo(file)) { "could not store the history key" }
        return key
    }

    /**
     * Set the stored key aside with the history it could not open (audit A-06); the next
     * [load] makes a new one. The Keystore key stays, so a key set aside that it still
     * unwraps can open its history again. [delete] deletes it.
     */
    fun setAside(context: Context) {
        val file = file(context)
        if (file.exists()) check(file.renameTo(setAsideFile(context))) { "could not set the history key aside" }
    }

    /** Forget the key for good, and any set aside: the history it opened can never be read again. */
    fun delete(context: Context) {
        file(context).delete()
        setAsideFile(context).delete()
        keyStore().deleteEntry(ALIAS)
    }

    private fun file(context: Context) = File(context.noBackupFilesDir, FILE)

    private fun setAsideFile(context: Context) = File(context.noBackupFilesDir, FILE + SET_ASIDE)

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun wrappingKey(): SecretKey {
        (keyStore().getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    /** IV (chosen by the Keystore) followed by the encrypted key and its tag. */
    private fun wrap(key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
        check(cipher.iv.size == IV_BYTES) { "unexpected IV length" }
        return cipher.iv + cipher.doFinal(key)
    }

    private fun unwrap(stored: ByteArray): ByteArray {
        val wrapping = keyStore().getKey(ALIAS, null) as? SecretKey
            ?: throw Lost("the Keystore key for the history is gone")
        if (stored.size < IV_BYTES + TAG_BITS / 8) throw Lost("the stored key is cut short")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        return try {
            cipher.init(Cipher.DECRYPT_MODE, wrapping, GCMParameterSpec(TAG_BITS, stored, 0, IV_BYTES))
            cipher.doFinal(stored, IV_BYTES, stored.size - IV_BYTES)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw Lost("the Keystore key for the history was invalidated", e)
        } catch (e: AEADBadTagException) {
            throw Lost("the stored key fails its check", e)
        }
    }
}
