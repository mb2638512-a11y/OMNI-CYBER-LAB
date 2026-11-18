package com.omni.cyberlab

import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URI
import java.net.URL
import java.security.MessageDigest

data class AuthorizationProbeResult(
    val statusCode: Int,
    val bodyBytes: Int,
    val bodySha256: String,
    val elapsedMs: Long
)

object AuthorizationBoundaryProbe {
    private const val MAX_BODY_BYTES = 64 * 1024

    fun compareAccounts(endpoint: String, allowedHosts: Set<String>, tokenA: String, tokenB: String): Pair<AuthorizationProbeResult, AuthorizationProbeResult> {
        require(tokenA.isNotBlank() && tokenB.isNotBlank()) { "Both short-lived client test-account tokens are required." }
        require(tokenA != tokenB) { "Use two distinct test-account sessions." }
        val uri = URI(endpoint.trim()).normalize()
        require(uri.scheme.equals("https", true)) { "HTTPS is required." }
        require(uri.userInfo == null && uri.fragment == null) { "URL user-info and fragments are not allowed." }
        require(uri.port == -1 || uri.port == 443) { "Only the standard HTTPS port is allowed." }
        val host = (uri.host ?: error("A valid hostname is required.")).lowercase()
        val hosts = allowedHosts.map { it.trim().lowercase().removePrefix("https://").removeSuffix("/") }.filter { it.isNotBlank() }.toSet()
        require(host in hosts) { "Hostname is not in the engagement allowlist." }
        val addresses = InetAddress.getAllByName(host)
        require(addresses.isNotEmpty() && addresses.none { it.isAnyLocalAddress || it.isLoopbackAddress || it.isLinkLocalAddress || it.isSiteLocalAddress || it.isMulticastAddress }) { "Private, local or special-use destinations are blocked." }
        return request(uri.toURL(), tokenA) to request(uri.toURL(), tokenB)
    }

    private fun request(url: URL, token: String): AuthorizationProbeResult {
        val started = System.nanoTime()
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 7000
            readTimeout = 7000
            instanceFollowRedirects = false
            useCaches = false
            setRequestProperty("Authorization", "Bearer $token")
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Cache-Control", "no-store")
        }
        try {
            val status = connection.responseCode
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val digest = MessageDigest.getInstance("SHA-256")
            var count = 0
            stream?.use { input ->
                val buffer = ByteArray(4096)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    count += read
                    require(count <= MAX_BODY_BYTES) { "Response exceeds the 64 KB safety limit." }
                    digest.update(buffer, 0, read)
                }
            }
            val hash = digest.digest().joinToString("") { "%02x".format(it) }
            return AuthorizationProbeResult(status, count, hash, (System.nanoTime() - started) / 1_000_000)
        } finally {
            connection.disconnect()
        }
    }
}
