package com.omni.cyberlab

import android.content.Context
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.foundation.layout.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.json.JSONArray
import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object SecureWorkspaceBackup {
    private val magic = byteArrayOf(0x4f, 0x43, 0x42, 0x31)
    private const val ITERATIONS = 250_000
    private const val MAX_BACKUP = 32 * 1024 * 1024

    private fun derive(passphrase: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(passphrase, salt, ITERATIONS, 256)
        return try { SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded } finally { spec.clearPassword() }
    }

    fun encrypt(plain: ByteArray, passphrase: CharArray): ByteArray {
        require(passphrase.size >= 12) { "Use a backup passphrase of at least 12 characters." }
        require(plain.size <= MAX_BACKUP) { "Workspace backup exceeds 20 MB." }
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val key = derive(passphrase, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        val encrypted = cipher.doFinal(plain)
        return magic + salt + cipher.iv + encrypted
    }

    fun decrypt(blob: ByteArray, passphrase: CharArray): ByteArray {
        require(passphrase.size >= 12) { "Backup passphrase must be at least 12 characters." }
        require(blob.size in 48..(MAX_BACKUP + 64) && blob.copyOfRange(0, 4).contentEquals(magic)) { "Unsupported or invalid backup file." }
        val salt = blob.copyOfRange(4, 20)
        val iv = blob.copyOfRange(20, 32)
        val key = derive(passphrase, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return cipher.doFinal(blob.copyOfRange(32, blob.size))
    }

    fun snapshot(context: Context, packageName: String, engagementId: String): ByteArray {
        val prefsName = if (engagementId == "default") "omni_blackbox_$packageName" else "omni_blackbox_${packageName}_$engagementId"
        val prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
        val values = JSONObject()
        prefs.all.forEach { (key, value) ->
            if (key != "secure_evidence_index" && key != "authorized") when (value) {
                is String -> values.put(key, value)
                is Boolean -> values.put(key, value)
                is Int -> values.put(key, value)
                is Long -> values.put(key, value)
                is Float -> values.put(key, value.toDouble())
                is Set<*> -> values.put(key, org.json.JSONArray(value.filterIsInstance<String>()))
            }
        }
        val evidenceIndex = runCatching { JSONArray(prefs.getString("secure_evidence_index", "[]")) }.getOrElse { JSONArray() }
        val evidencePayload = JSONArray()
        for (index in 0 until evidenceIndex.length()) {
            val item = evidenceIndex.optJSONObject(index) ?: continue
            val bytes = SecureEvidenceVault.read(context, engagementId, item.optString("id"))
            evidencePayload.put(JSONObject().put("label", item.optString("label")).put("data", Base64.encodeToString(bytes, Base64.NO_WRAP)))
        }
        val payload = JSONObject().put("format", "OMNI-CYBER-LAB-WORKSPACE").put("version", 1)
            .put("packageName", packageName).put("engagementId", engagementId).put("preferences", values).put("evidenceFiles", evidencePayload)
        return payload.toString().toByteArray(Charsets.UTF_8)
    }

    fun restore(context: Context, packageName: String, engagementId: String, payload: ByteArray) {
        require(payload.size <= MAX_BACKUP) { "Workspace backup is too large." }
        val json = JSONObject(payload.toString(Charsets.UTF_8))
        require(json.optString("format") == "OMNI-CYBER-LAB-WORKSPACE" && json.optInt("version") == 1) { "Unsupported workspace backup format." }
        require(json.optString("packageName") == packageName) { "Backup belongs to a different app package." }
        val values = json.getJSONObject("preferences")
        val prefsName = if (engagementId == "default") "omni_blackbox_$packageName" else "omni_blackbox_${packageName}_$engagementId"
        val editor = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE).edit().clear()
        val keys = values.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            val value = values.get(key)
            when (value) {
                is String -> editor.putString(key, value)
                is Boolean -> editor.putBoolean(key, value)
                is Int -> editor.putInt(key, value)
                is Long -> editor.putLong(key, value)
                is Double -> editor.putFloat(key, value.toFloat())
                is org.json.JSONArray -> editor.putStringSet(key, (0 until value.length()).map { value.optString(it) }.toSet())
            }
        }
        val evidenceFiles = json.optJSONArray("evidenceFiles") ?: JSONArray()
        require(evidenceFiles.length() <= 50) { "Backup contains more than 50 evidence files." }
        val decodedEvidence = (0 until evidenceFiles.length()).map { index ->
            val item = evidenceFiles.getJSONObject(index)
            val bytes = Base64.decode(item.optString("data"), Base64.NO_WRAP)
            require(bytes.isNotEmpty() && bytes.size <= 10 * 1024 * 1024) { "Backup contains an invalid or oversized evidence attachment." }
            item.optString("label") to bytes
        }
        require(decodedEvidence.sumOf { it.second.size.toLong() } <= 20L * 1024L * 1024L) { "Backup evidence exceeds the 20 MB workspace limit." }
        editor.putBoolean("authorized", false).putString("secure_evidence_index", "[]").apply()
        SecureEvidenceVault.clear(context, engagementId)
        val restoredEvidence = JSONArray()
        decodedEvidence.forEach { (label, bytes) ->
            val record = SecureEvidenceVault.importBytes(context, engagementId, label, bytes)
            restoredEvidence.put(record)
        }
        context.getSharedPreferences(prefsName, Context.MODE_PRIVATE).edit().putString("secure_evidence_index", restoredEvidence.toString()).apply()
    }
}