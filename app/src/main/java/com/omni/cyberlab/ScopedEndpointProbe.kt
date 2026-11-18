package com.omni.cyberlab

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection
import org.json.JSONObject

data class ScopedProbeResult(
    val safeUrl: String,
    val statusCode: Int,
    val durationMs: Long,
    val contentType: String,
    val contentLength: String,
    val securityHeaders: Map<String, String>,
    val tlsProtocol: String,
    val tlsCipher: String,
    val certificateSubject: String,
    val certificateIssuer: String,
    val certificateSha256: String,
    val certificateNotBefore: String,
    val certificateNotAfter: String,
    val certificateValidNow: Boolean,
    val certificateDaysRemaining: Long,
    val bodyBytesRead: Int,
    val bodySha256: String,
    val note: String
) {
    fun toJson(): JSONObject = JSONObject()
        .put("url", safeUrl).put("statusCode", statusCode).put("durationMs", durationMs)
        .put("contentType", contentType).put("contentLength", contentLength)
        .put("securityHeaders", JSONObject(securityHeaders))
        .put("tlsProtocol", tlsProtocol).put("tlsCipher", tlsCipher)
        .put("certificateSubject", certificateSubject).put("certificateIssuer", certificateIssuer)
                .put("certificateSha256", certificateSha256)
        .put("certificateNotBefore", certificateNotBefore).put("certificateNotAfter", certificateNotAfter)
        .put("certificateValidNow", certificateValidNow).put("certificateDaysRemaining", certificateDaysRemaining)
        .put("bodyBytesRead", bodyBytesRead)
        .put("bodySha256", bodySha256).put("note", note)
}

suspend fun runScopedEndpointProbe(rawUrl: String, allowedHosts: Set<String>, method: String): ScopedProbeResult = withContext(Dispatchers.IO) {
    require(method == "GET" || method == "HEAD") { "Only GET and HEAD are supported." }
    val uri = URI(rawUrl.trim())
    require(uri.scheme.equals("https", true)) { "Only HTTPS endpoints are permitted." }
    val host = (uri.host ?: error("A valid hostname is required.")).lowercase()
    require(host in allowedHosts.map { it.lowercase() }.toSet()) { "Host is not in the client-approved allowlist." }
    require(uri.userInfo == null) { "Credentials in endpoint URLs are not accepted." }
    require(uri.port == -1 || uri.port == 443) { "Only the standard HTTPS port 443 is supported by this probe." }
    val safeUrl = URI("https", null, host, uri.port, uri.path.ifBlank { "/" }, null, null).toString()
    val connection = (URL(uri.toString()).openConnection() as HttpsURLConnection).apply {
        requestMethod = method
        connectTimeout = 7000
        readTimeout = 7000
        instanceFollowRedirects = false
        useCaches = false
        setRequestProperty("User-Agent", "OMNI-CYBER-LAB-Authorized-Assessment/1.0")
        setRequestProperty("Accept", "*/*")
    }
    val started = System.nanoTime()
    try {
        val status = connection.responseCode
        val duration = (System.nanoTime() - started) / 1_000_000L
        val headerNames = listOf("Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "Cache-Control", "Server", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers")
        val headers = headerNames.mapNotNull { key -> connection.getHeaderField(key)?.let { key to it.take(512) } }.toMap().toMutableMap()
        // Store cookie security attributes only; never persist cookie names or values.
        connection.headerFields.entries.filter { it.key.equals("Set-Cookie", true) }.flatMap { it.value.orEmpty() }.take(20).forEachIndexed { index, cookie ->
            val lower = cookie.lowercase()
            val flags = listOf("Secure", "HttpOnly", "SameSite=Strict", "SameSite=Lax", "SameSite=None").filter { lower.contains(it.lowercase()) }
            headers["Set-Cookie-Flags-$index"] = flags.joinToString(",").ifBlank { "NO_SECURITY_FLAGS_OBSERVED" }
        }
        val body = if (method == "GET") (if (status >= 400) connection.errorStream else connection.inputStream)?.use { input ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            var total = 0
            while (total < 65536) {
                val count = input.read(buffer, 0, minOf(buffer.size, 65536 - total))
                if (count <= 0) break
                output.write(buffer, 0, count)
                total += count
            }
            output.toByteArray()
        } ?: ByteArray(0) else ByteArray(0)
        val cert = connection.serverCertificates.firstOrNull() as? java.security.cert.X509Certificate
        val certHash = cert?.encoded?.let { MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { b -> "%02X".format(b) } } ?: ""
        val certValidNow = cert?.let { runCatching { it.checkValidity(); true }.getOrDefault(false) } ?: false
        val certDaysRemaining = cert?.let { (it.notAfter.time - System.currentTimeMillis()) / 86_400_000L } ?: -1L
        ScopedProbeResult(safeUrl, status, duration, connection.contentType ?: "", connection.getHeaderField("Content-Length") ?: "", headers, "", connection.cipherSuite ?: "", cert?.subjectX500Principal?.name ?: "", cert?.issuerX500Principal?.name ?: "", certHash, cert?.notBefore?.toString() ?: "", cert?.notAfter?.toString() ?: "", certValidNow, certDaysRemaining, body.size, if (body.isNotEmpty()) MessageDigest.getInstance("SHA-256").digest(body).joinToString("") { "%02X".format(it) } else "", "One HTTPS request only; redirects are not followed; response body is not stored. HTTP status and missing headers require manual interpretation.")
    } finally { connection.disconnect() }
}