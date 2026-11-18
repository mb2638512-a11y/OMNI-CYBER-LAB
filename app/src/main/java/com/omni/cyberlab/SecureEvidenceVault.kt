package com.omni.cyberlab

import android.content.Context
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.text.DateFormat
import java.util.Date
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** App-private, per-engagement AES-256-GCM evidence storage. */
object SecureEvidenceVault {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val MAX_BYTES = 10L * 1024L * 1024L
    private val magic = byteArrayOf(0x4f, 0x43, 0x4c, 0x31)

    private fun scopeId(context: Context, engagementId: String): String =
        MessageDigest.getInstance("SHA-256").digest("${context.packageName}:$engagementId".toByteArray()).joinToString("") { "%02x".format(it) }.take(32)

    private fun directory(context: Context, engagementId: String): File =
        File(File(context.filesDir, "secure-evidence"), scopeId(context, engagementId)).apply { mkdirs() }

    private fun alias(context: Context, engagementId: String) = "omni_evidence_${scopeId(context, engagementId)}"

    private fun key(context: Context, engagementId: String): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val name = alias(context, engagementId)
        (store.getKey(name, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(KeyGenParameterSpec.Builder(name, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).setRandomizedEncryptionRequired(true).build())
        return generator.generateKey()
    }

    fun import(context: Context, engagementId: String, uri: Uri, label: String): JSONObject {
        val bytes = context.contentResolver.openInputStream(uri)?.use { input ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            var total = 0L
            while (true) { val count = input.read(buffer); if (count < 0) break; total += count; require(total <= MAX_BYTES) { "Evidence file exceeds the 10 MB limit." }; output.write(buffer, 0, count) }
            output.toByteArray()
        } ?: error("Cannot read selected evidence file.")
        return importBytes(context, engagementId, label, bytes)
    }

    fun importBytes(context: Context, engagementId: String, label: String, bytes: ByteArray): JSONObject {
        require(bytes.isNotEmpty() && bytes.size.toLong() <= MAX_BYTES) { "Evidence file must be between 1 byte and 10 MB." }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key(context, engagementId))
        val encrypted = cipher.doFinal(bytes)
        val id = UUID.randomUUID().toString()
        val target = File(directory(context, engagementId), "$id.bin")
        target.outputStream().use { output -> output.write(magic); output.write(cipher.iv); output.write(encrypted) }
        return JSONObject().put("id", id).put("label", label.trim().ifBlank { "Evidence attachment" }.take(100))
            .put("bytes", bytes.size).put("savedAt", DateFormat.getDateTimeInstance().format(Date())).put("encryption", "AES-256-GCM / Android Keystore")
    }
    fun read(context: Context, engagementId: String, id: String): ByteArray {
        require(id.matches(Regex("[0-9a-fA-F-]{36}"))) { "Invalid evidence identifier." }
        val file = File(directory(context, engagementId), "$id.bin")
        require(file.isFile && file.length() <= MAX_BYTES + 64) { "Encrypted evidence file is missing or too large." }
        val packed = file.readBytes()
        require(packed.size > 32 && packed.copyOfRange(0, 4).contentEquals(magic)) { "Evidence file format is invalid." }
        val iv = packed.copyOfRange(4, 16)
        val encrypted = packed.copyOfRange(16, packed.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(context, engagementId), GCMParameterSpec(128, iv))
        return cipher.doFinal(encrypted)
    }

    fun delete(context: Context, engagementId: String, id: String) {
        require(id.matches(Regex("[0-9a-fA-F-]{36}"))) { "Invalid evidence identifier." }
        File(directory(context, engagementId), "$id.bin").delete()
    }

    fun clear(context: Context, engagementId: String) {
        directory(context, engagementId).deleteRecursively()
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        store.deleteEntry(alias(context, engagementId))
    }
}