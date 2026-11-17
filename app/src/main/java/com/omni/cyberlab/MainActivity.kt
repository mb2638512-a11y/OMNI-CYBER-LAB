package com.omni.cyberlab

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.PackageInfo
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.pdf.PdfDocument
import android.graphics.drawable.Drawable
import android.net.Uri
import android.content.Intent
import androidx.core.content.FileProvider
import android.provider.Settings
import android.app.AppOpsManager
import android.app.usage.StorageStatsManager
import android.os.storage.StorageManager
import android.os.Process
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import java.io.File
import java.util.zip.ZipFile
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku
import java.security.MessageDigest
import java.net.URI
import javax.net.ssl.HttpsURLConnection
import java.security.cert.X509Certificate

private val Bg = Color(0xFF08111F)
private val CardBg = Color(0xFF111F32)
private val Raised = Color(0xFF1A2B40)
private val Green = Color(0xFF35D6A0)
private val Grey = Color(0xFF91A2B8)
private val Orange = Color(0xFFFFC66D)
private val Red = Color(0xFFFF6878)
private val Blue = Color(0xFF72B7FF)

data class AppRow(
    val name: String, val pkg: String, val version: String, val icon: Bitmap?,
    val permissions: List<String>, val exported: Int, val debug: Boolean,
    val signer: String, val system: Boolean, val targetSdk: Int,
    val installer: String, val findings: List<String>, val grantedPermissions: List<String> = emptyList(), val exportedComponents: List<String> = emptyList(), val archiveInventory: List<String> = emptyList(), val apkPath: String? = null, val apkPaths: List<String> = emptyList()
) {
    val status: String get() = when {
        debug -> "HIGH RISK"
        findings.isNotEmpty() -> "REVIEW"
        else -> "INVENTORY ONLY"
    }
}


private fun inspectApkArchive(path: String?): List<String> {
    if (path.isNullOrBlank()) return listOf("Archive path unavailable")
    return try {
        val fileDigest = MessageDigest.getInstance("SHA-256")
        File(path).inputStream().use { input ->
            val buffer = ByteArray(8192)
            while (true) { val count = input.read(buffer); if (count <= 0) break; fileDigest.update(buffer, 0, count) }
        }
        val apkSha256 = fileDigest.digest().joinToString("") { "%02X".format(it) }
        ZipFile(path).use { zip ->
            val entries = zip.entries().asSequence().toList()
            val dex = entries.filter { it.name.matches(Regex("classes([0-9]*)\\.dex")) }.map { it.name }.sorted()
            val native = entries.filter { it.name.startsWith("lib/") && it.name.endsWith(".so") }.map { it.name }.sorted()
            val networkConfig = entries.filter { it.name.contains("network_security_config", ignoreCase = true) }.map { it.name }
            val reviewFiles = entries.filter { entry -> listOf(".json", ".properties", ".xml", ".pem", ".cer", ".crt", ".db", ".sqlite").any { entry.name.endsWith(it, ignoreCase = true) } }
            val totalUncompressed = entries.sumOf { it.size.coerceAtLeast(0L) }
            val textCandidates = entries.filter { entry ->
                !entry.isDirectory && entry.size in 1..131072 &&
                    listOf(".json", ".properties", ".xml", ".txt", ".js", ".html", ".yaml", ".yml", ".gradle", ".kt").any { entry.name.endsWith(it, ignoreCase = true) }
            }.take(80)
            var scannedBytes = 0L
            val secretSignals = mutableListOf<String>()
            val networkConfigSignals = mutableListOf<String>()
            val assignmentPattern = Regex("""(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|private[_-]?key|password|secret)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{12,})""")
            val awsPattern = Regex("""\bAKIA[0-9A-Z]{16}\b""")
            textCandidates.forEach { entry ->
                if (scannedBytes >= 2L * 1024L * 1024L) return@forEach
                try {
                    val remaining = (2L * 1024L * 1024L - scannedBytes).coerceAtMost(131072L).toInt()
                    val bytes = zip.getInputStream(entry).use { input ->
                        val output = java.io.ByteArrayOutputStream()
                        val buffer = ByteArray(8192)
                        var left = remaining
                        while (left > 0) {
                            val count = input.read(buffer, 0, minOf(buffer.size, left))
                            if (count <= 0) break
                            output.write(buffer, 0, count)
                            left -= count
                        }
                        output.toByteArray()
                    }
                    scannedBytes += bytes.size
                    val content = bytes.toString(Charsets.UTF_8)
                    if (entry.name.contains("network_security_config", ignoreCase = true) || entry.name.endsWith(".xml", ignoreCase = true)) {
                        if (Regex("""(?i)cleartextTrafficPermitted\s*=\s*["']true["']""").containsMatchIn(content)) {
                            networkConfigSignals.add("Cleartext traffic explicitly permitted • ${entry.name}")
                        }
                        if (Regex("""(?i)<certificates[^>]+src\s*=\s*["']user["']""").containsMatchIn(content)) {
                            networkConfigSignals.add("User-added certificate trust anchor present • ${entry.name}; review intended debug-only use")
                        }
                        if (Regex("""(?i)<debug-overrides""").containsMatchIn(content)) {
                            networkConfigSignals.add("Debug certificate overrides present • ${entry.name}; verify release build behavior")
                        }
                    }
                    assignmentPattern.findAll(content).take(4).forEach { match ->
                        val keyName = match.groupValues[1]
                        secretSignals.add("Possible embedded credential • $keyName • value redacted • ${entry.name}")
                    }
                    if (awsPattern.containsMatchIn(content)) {
                        secretSignals.add("Possible AWS access-key identifier • value redacted • ${entry.name}")
                    }
                } catch (_: Exception) { }
            }
            val dexSignals = mutableListOf<String>()
            var dexBytesScanned = 0L
            val sensitiveDexPattern = Regex("""(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|private[_-]?key|password)\s*[:=]\s*["']?[A-Za-z0-9_./+=-]{12,}""")
            val urlPattern = Regex("""https?://[^\s"'<>]{8,}""")
            val behaviorMarkers = listOf(
                "Runtime.getRuntime", "ProcessBuilder", "DexClassLoader", "PathClassLoader",
                "AccessibilityService", "MediaProjection", "SmsManager", "DevicePolicyManager",
                "addJavascriptInterface", "setJavaScriptEnabled", "requestInstallPackages"
            )
            dex.take(12).forEach { dexEntry ->
                if (dexBytesScanned >= 12L * 1024L * 1024L) return@forEach
                try {
                    val maxRead = (12L * 1024L * 1024L - dexBytesScanned).coerceAtMost(2L * 1024L * 1024L).toInt()
                    val dexFile = zip.getEntry(dexEntry) ?: return@forEach
                    val bytes = zip.getInputStream(dexFile).use { input ->
                        val out = java.io.ByteArrayOutputStream()
                        val buffer = ByteArray(8192)
                        var remaining = maxRead
                        while (remaining > 0) {
                            val count = input.read(buffer, 0, minOf(buffer.size, remaining))
                            if (count <= 0) break
                            out.write(buffer, 0, count)
                            remaining -= count
                        }
                        out.toByteArray()
                    }
                    dexBytesScanned += bytes.size
                    val printable = bytes.toString(Charsets.ISO_8859_1)
                    sensitiveDexPattern.findAll(printable).take(8).forEach {
                        dexSignals.add("Possible credential-like DEX string • value redacted • $dexEntry")
                    }
                    urlPattern.findAll(printable).take(12).forEach { match ->
                        val safeHost = try { URI(match.value).host ?: "unparsed host" } catch (_: Exception) { "unparsed host" }
                        dexSignals.add("Embedded URL string • $safeHost • $dexEntry")
                    }
                    behaviorMarkers.filter { printable.contains(it, true) }.forEach {
                        dexSignals.add("Behavior/API marker • $it • $dexEntry")
                    }
                } catch (_: Exception) { }
            }
            val multidex = dex.size > 1
            buildList {
                add("APK SHA-256: $apkSha256")
                add("APK entries: ${entries.size}")
                add("Total uncompressed size: ${totalUncompressed / 1024} KB")
                add("Text files sampled for credential patterns: ${textCandidates.size}; bytes scanned: ${scannedBytes}")
                add("Network XML review signals: ${networkConfigSignals.size}")
                networkConfigSignals.take(20).forEach { add("NETWORK REVIEW • $it") }
                add("Possible credential signals: ${secretSignals.size}")
                secretSignals.take(30).forEach { add("SECRET REVIEW • $it") }
                if (secretSignals.isEmpty()) add("No credential patterns matched in sampled text files; this does not prove secrets are absent")
                add("Review-relevant config/data files: ${reviewFiles.size}")
                reviewFiles.take(50).forEach { entry -> add("FILE • ${entry.name} • ${entry.size.coerceAtLeast(0L) / 1024} KB") }
                add("DEX files: ${dex.size}" + if (multidex) " • multidex package" else "")
                add("DEX printable-string scan: ${dexBytesScanned / 1024} KB sampled • ${dexSignals.size} review signals")
                dexSignals.take(50).forEach { add("DEX REVIEW • $it") }
                add("DEX scan is string/marker triage, not decompilation or proof of runtime behavior.")
                dex.take(20).forEach { add("DEX • $it") }
                add("Native libraries: ${native.size}")
                native.take(30).forEach { add("NATIVE • $it") }
                if (networkConfig.isEmpty()) add("Network security config: not found by filename")
                else networkConfig.forEach { add("NETWORK CONFIG • $it") }
                if (entries.any { it.name == "assets/" } || entries.any { it.name.startsWith("assets/") }) {
                    add("Assets directory: present")
                }
                if (entries.any { it.name.startsWith("META-INF/") }) add("META-INF metadata: present")
                if (dex.isEmpty()) add("No standard classes*.dex entry detected")
            }
        }
    } catch (e: Exception) {
        listOf("Archive inspection failed: ${e.javaClass.simpleName}")
    }
}


private fun classifyFinding(finding: String): Pair<String, String> {
    val value = finding.lowercase()
    return when {
        value.contains("debuggable") -> "HIGH" to "Disable debuggable on production builds; keep debugging limited to development variants. (MASVS-RESILIENCE)"
        value.contains("cleartext") -> "MEDIUM" to "Disable cleartext traffic and configure domain-specific trust policy. Verify with runtime traffic tests. (MASVS-NETWORK)"
        value.contains("backup") -> "REVIEW" to "Review backup rules and exclude credentials, tokens and sensitive records where appropriate. (MASVS-STORAGE)"
        value.contains("sensitive permissions") -> "INFO" to "Confirm each permission is necessary, request it just-in-time and minimize collected data. (MASVS-PRIVACY)"
        value.contains("exported components") -> "REVIEW" to "Review each exported component's caller permissions, intent filters, input validation and exposed operations. (MASVS-PLATFORM)"
        value.contains("signing fingerprint") -> "INFO" to "Confirm signing certificate availability and compare fingerprints against a trusted release record. (MASVS-CODE)"
        else -> "REVIEW" to "Manually validate this signal and document evidence before assigning a vulnerability severity."
    }
}

private suspend fun inspectHttpsEndpoint(rawInput: String): List<String> = withContext(Dispatchers.IO) {
    val uri = try { URI(rawInput.trim()) } catch (_: Exception) {
        return@withContext listOf("Invalid URL format. Enter a complete https:// URL.")
    }
    if (!uri.scheme.equals("https", true) || uri.host.isNullOrBlank() || uri.userInfo != null) {
        return@withContext listOf("Only a valid HTTPS URL without embedded username/password is accepted.")
    }
    if (rawInput.length > 2048) return@withContext listOf("URL is too long.")
    var connection: HttpsURLConnection? = null
    try {
        val conn = uri.toURL().openConnection() as? HttpsURLConnection
            ?: return@withContext listOf("Could not create an HTTPS connection.")
        connection = conn
        conn.instanceFollowRedirects = false
        conn.requestMethod = "HEAD"
        conn.connectTimeout = 6000
        conn.readTimeout = 6000
        conn.useCaches = false
        conn.setRequestProperty("User-Agent", "OMNI-CYBER-LAB-Security-Audit/1.0")
        conn.connect()
        val results = mutableListOf<String>()
        results.add("Endpoint host: ${uri.host}")
        results.add("TLS protocol: negotiated protocol is not exposed by this Android connection API.")
        results.add("Cipher suite: ${conn.cipherSuite}")
        val cert = conn.serverCertificates.firstOrNull() as? X509Certificate
        if (cert != null) {
            results.add("Certificate subject: ${cert.subjectX500Principal.name}")
            results.add("Certificate issuer: ${cert.issuerX500Principal.name}")
            results.add("Certificate expires: ${cert.notAfter}")
            try { cert.checkValidity(); results.add("Certificate validity: CURRENT") }
            catch (_: Exception) { results.add("Certificate validity: EXPIRED OR NOT YET VALID — investigate") }
        } else results.add("Certificate details unavailable from peer.")
        val status = conn.responseCode
        results.add("HTTP response: $status")
        if (status in 300..399) results.add("Redirect returned; it was not followed.")
        fun header(name: String): String = conn.getHeaderField(name)?.take(300) ?: "MISSING"
        val hsts = header("Strict-Transport-Security")
        val csp = header("Content-Security-Policy")
        val xcto = header("X-Content-Type-Options")
        val xfo = header("X-Frame-Options")
        results.add("Strict-Transport-Security: $hsts")
        results.add("Content-Security-Policy: $csp")
        results.add("X-Content-Type-Options: $xcto")
        results.add("X-Frame-Options: $xfo")
        if (hsts == "MISSING") results.add("REVIEW: HSTS header not observed on this response.")
        if (csp == "MISSING") results.add("REVIEW: CSP header not observed; applicability depends on response content.")
        if (xcto == "MISSING") results.add("REVIEW: X-Content-Type-Options header not observed.")
        results.add("Method used: HEAD only • no credentials • no request body • redirects disabled.")
        results
    } catch (e: Exception) {
        listOf("Connection check failed: ${e.javaClass.simpleName}: ${e.message ?: "no details"}", "No vulnerability conclusion can be drawn from a failed connection.")
    } finally { connection?.disconnect() }
}

class MainActivity : ComponentActivity() {
    private fun iconBitmap(drawable: Drawable): Bitmap? = try {
        val w = drawable.intrinsicWidth.coerceAtLeast(1).coerceAtMost(160)
        val h = drawable.intrinsicHeight.coerceAtLeast(1).coerceAtMost(160)
        Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).also {
            drawable.setBounds(0, 0, w, h); drawable.draw(Canvas(it))
        }
    } catch (_: Exception) { null }

    private fun readApps(): List<AppRow> {
        val pm = packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or
            PackageManager.GET_PROVIDERS or
            (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else 0)
        return pm.getInstalledPackages(flags).mapNotNull { p ->
            try {
                val ai = p.applicationInfo ?: return@mapNotNull null
                val perms = p.requestedPermissions?.toList() ?: emptyList()
                val grantedPermissions = p.requestedPermissions?.mapIndexedNotNull { index, permission ->
                    val permissionFlags = p.requestedPermissionsFlags?.getOrNull(index) ?: 0
                    if (permissionFlags and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0) permission else null
                } ?: emptyList()
                val debug = ai.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
                val componentDetails = buildList {
                    p.activities?.filter { it.exported }?.forEach { add("ACTIVITY • ${it.name} • permission=${it.permission ?: "none"}") }
                    p.services?.filter { it.exported }?.forEach { add("SERVICE • ${it.name} • permission=${it.permission ?: "none"}") }
                    p.receivers?.filter { it.exported }?.forEach { add("RECEIVER • ${it.name} • permission=${it.permission ?: "none"}") }
                    p.providers?.filter { it.exported }?.forEach { add("PROVIDER • ${it.name} • permission=${it.readPermission ?: "none"}/${it.writePermission ?: "none"}") }
                }
                val exported = componentDetails.size
                val cert = if (Build.VERSION.SDK_INT >= 28)
                    p.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray() else null
                val signer = cert?.let { bytes ->
                    MessageDigest.getInstance("SHA-256").digest(bytes)
                        .joinToString(":") { "%02X".format(it) }
                } ?: "Unavailable"
                val findings = buildList {
                    if (debug) add("Debuggable build flag is enabled")
                    if (ai.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0) add("App backup is enabled; review sensitive-data backup rules")
                    if (Build.VERSION.SDK_INT >= 23 && (ai.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0)) add("Cleartext network traffic is allowed by manifest")
                    if (perms.any { it.contains("SMS") || it.contains("CONTACTS") ||
                            it.contains("LOCATION") || it.contains("CAMERA") ||
                            it.contains("RECORD_AUDIO") }) add("Sensitive permissions requested")
                    if (exported > 0) add("$exported exported components need access-control review")
                    if (signer == "Unavailable") add("Signing fingerprint unavailable")
                }
                val installer = if (Build.VERSION.SDK_INT >= 30) {
                    try { pm.getInstallSourceInfo(p.packageName).installingPackageName ?: "Unknown" }
                    catch (_: Exception) { "Unknown" }
                } else "Not available on Android version"
                AppRow(pm.getApplicationLabel(ai).toString(), p.packageName,
                    p.versionName ?: "Unknown", iconBitmap(pm.getApplicationIcon(ai)),
                    perms, exported, debug, signer,
                    ai.flags and ApplicationInfo.FLAG_SYSTEM != 0,
                    ai.targetSdkVersion, installer, findings, grantedPermissions, componentDetails, inspectApkArchive(ai.sourceDir), ai.sourceDir, (listOf(ai.sourceDir) + (ai.splitSourceDirs?.toList() ?: emptyList())).distinct())
            } catch (_: Exception) { null }
        }.sortedBy { it.name.lowercase() }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(
                primary = Green, onPrimary = Bg, background = Bg, surface = CardBg,
                onSurface = Color.White, surfaceVariant = Raised, onSurfaceVariant = Grey
            )) {
                var apps by remember { mutableStateOf(emptyList<AppRow>()) }
                var selected by remember { mutableStateOf<AppRow?>(null) }
                var query by remember { mutableStateOf("") }
                var filter by remember { mutableStateOf("ALL") }
                var riskFirst by remember { mutableStateOf(false) }
                var scanning by remember { mutableStateOf(false) }
                var scanTime by remember { mutableStateOf("Waiting for first inventory") }
                var bridge by remember { mutableStateOf("Checking Shizuku…") }
                var settings by remember { mutableStateOf(false) }
                var showAuthorization by remember { mutableStateOf(false) }
                var importMessage by remember { mutableStateOf("") }
                val context = androidx.compose.ui.platform.LocalContext.current
                val scope = rememberCoroutineScope()
                val apkPicker = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocument()
                ) { uri: Uri? ->
                    if (uri != null) {
                        scope.launch {
                            importMessage = "Reading APK metadata…"
                            try {
                                val imported = withContext(Dispatchers.IO) {
                                    val file = File.createTempFile("omni-audit-", ".apk", context.cacheDir)
                                    context.contentResolver.openInputStream(uri)?.use { input ->
                                        file.outputStream().use { output -> input.copyTo(output) }
                                    } ?: throw IllegalStateException("Cannot read selected file")
                                    val pm = context.packageManager
                                    val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or
                                        PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or
                                        PackageManager.GET_PROVIDERS or
                                        (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else 0)
                                    val info = pm.getPackageArchiveInfo(file.absolutePath, flags)
                                        ?: throw IllegalArgumentException("Not a readable Android APK")
                                    val ai = info.applicationInfo ?: throw IllegalArgumentException("APK metadata missing")
                                    ai.sourceDir = file.absolutePath
                                    ai.publicSourceDir = file.absolutePath
                                    val perms = info.requestedPermissions?.toList() ?: emptyList()
                                    val debug = ai.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
                                    val componentDetails = buildList {
                                        info.activities?.filter { it.exported }?.forEach { add("ACTIVITY • ${it.name} • permission=${it.permission ?: "none"}") }
                                        info.services?.filter { it.exported }?.forEach { add("SERVICE • ${it.name} • permission=${it.permission ?: "none"}") }
                                        info.receivers?.filter { it.exported }?.forEach { add("RECEIVER • ${it.name} • permission=${it.permission ?: "none"}") }
                                        info.providers?.filter { it.exported }?.forEach { add("PROVIDER • ${it.name} • permission=${it.readPermission ?: "none"}/${it.writePermission ?: "none"}") }
                                    }
                                    val exported = componentDetails.size
                                    val cert = if (Build.VERSION.SDK_INT >= 28)
                                        info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray() else null
                                    val signer = cert?.let { bytes ->
                                        MessageDigest.getInstance("SHA-256").digest(bytes)
                                            .joinToString(":") { "%02X".format(it) }
                                    } ?: "Unavailable"
                                    val findings = buildList {
                                        if (debug) add("Debuggable build flag is enabled")
                                        if (ai.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0) add("App backup is enabled; review sensitive-data backup rules")
                                        if (Build.VERSION.SDK_INT >= 23 && (ai.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0)) add("Cleartext network traffic is allowed by manifest")
                                        if (perms.any { it.contains("SMS") || it.contains("CONTACTS") ||
                                            it.contains("LOCATION") || it.contains("CAMERA") ||
                                            it.contains("RECORD_AUDIO") }) add("Sensitive permissions requested")
                                        if (exported > 0) add("$exported exported components need access-control review")
                                        if (signer == "Unavailable") add("Signing fingerprint unavailable")
                                    }
                                    val icon = try {
                                        val d = pm.getApplicationIcon(ai)
                                        val w = d.intrinsicWidth.coerceAtLeast(1).coerceAtMost(160)
                                        val h = d.intrinsicHeight.coerceAtLeast(1).coerceAtMost(160)
                                        Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).also {
                                            d.setBounds(0, 0, w, h); d.draw(Canvas(it))
                                        }
                                    } catch (_: Exception) { null }
                                    AppRow(pm.getApplicationLabel(ai).toString(), info.packageName,
                                        info.versionName ?: "Unknown", icon, perms, exported, debug,
                                        signer, false, ai.targetSdkVersion, "Imported APK • not installed", findings, emptyList(), componentDetails, inspectApkArchive(file.absolutePath), file.absolutePath, listOf(file.absolutePath))
                                }
                                selected = imported
                                importMessage = "APK metadata loaded. Runtime behavior is not tested."
                            } catch (e: Exception) {
                                importMessage = "Could not inspect APK: ${e.message}"
                            }
                        }
                    }
                }
                fun scan() {
                    scope.launch {
                        scanning = true
                        try {
                            apps = withContext(Dispatchers.IO) { readApps() }
                            scanTime = "Inventory refreshed • " + java.text.SimpleDateFormat(
                                "HH:mm", java.util.Locale.getDefault()).format(java.util.Date())
                        } finally { scanning = false }
                    }
                }
                fun bridgeStatus() {
                    bridge = try {
                        when {
                            !Shizuku.pingBinder() -> "Service not running"
                            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED -> "Connected • permission granted"
                            else -> "Connected • permission required"
                        }
                    } catch (e: Exception) { "Unavailable: ${e.message}" }
                }
                LaunchedEffect(Unit) { scan(); bridgeStatus() }
                val review = apps.count { it.findings.isNotEmpty() }
                val high = apps.count { it.debug }
                val shown = apps.filter {
                    (it.name.contains(query, true) || it.pkg.contains(query, true)) &&
                    when (filter) {
                        "REVIEW" -> it.findings.isNotEmpty()
                        "USER" -> !it.system
                        "SYSTEM" -> it.system
                        else -> true
                    }
                }.let { list ->
                    if (riskFirst) list.sortedWith(compareByDescending<AppRow> { it.debug }
                        .thenByDescending { it.findings.size }.thenBy { it.name.lowercase() })
                    else list.sortedBy { it.name.lowercase() }
                }
                if (showAuthorization) {
                    AlertDialog(
                        onDismissRequest = { showAuthorization = false },
                        title = { Text("Authorized app testing") },
                        text = { Text("Only choose an APK you own or have explicit permission to assess. This first pass reads package metadata and signing details; it does not install or execute the APK, access private app data, or prove the app is safe.") },
                        confirmButton = {
                            TextButton(onClick = {
                                showAuthorization = false
                                apkPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream"))
                            }) { Text("I have permission • Choose APK") }
                        },
                        dismissButton = {
                            TextButton(onClick = { showAuthorization = false }) { Text("Cancel") }
                        }
                    )
                }
                Surface(Modifier.fillMaxSize(), color = Bg) {
                    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
                        Spacer(Modifier.height(7.dp))
                        Row(Modifier.fillMaxWidth().padding(vertical = 7.dp),
                            verticalAlignment = Alignment.CenterVertically) {
                            Surface(color = Raised, shape = RoundedCornerShape(12.dp)) {
                                Icon(Icons.Default.Shield, null, tint = Green,
                                    modifier = Modifier.padding(10.dp).size(25.dp))
                            }
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text("OMNI CYBER LAB", fontSize = 17.sp, fontWeight = FontWeight.ExtraBold)
                                Text(if (settings) "CONTROL CENTER" else "INSTALLED APPLICATIONS",
                                    color = Grey, fontSize = 9.sp, letterSpacing = 1.5.sp)
                            }
                            IconButton(onClick = { settings = !settings }) {
                                if (settings) Icon(Icons.Default.ArrowBack, "Back to apps", tint = Green)
                                else Icon(Icons.Default.Settings, "Settings", tint = Green)
                            }
                        }
                        when {
                            selected != null -> Detail(selected!!, onBack = { selected = null })
                            settings -> LazyColumn(
                                Modifier.fillMaxSize(),
                                contentPadding = PaddingValues(top = 8.dp, bottom = 28.dp),
                                verticalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                item {
                                    Text("Security settings", fontSize = 23.sp, fontWeight = FontWeight.Bold)
                                    Text("Device overview and diagnostic controls", color = Grey, fontSize = 12.sp)
                                }
                                item {
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Metric("INSTALLED", apps.size.toString(), "Apps found", Blue, Modifier.weight(1f))
                                        Metric("REVIEW", review.toString(), "Need attention", Orange, Modifier.weight(1f))
                                        Metric("HIGH RISK", high.toString(), "Debug flag", Red, Modifier.weight(1f))
                                    }
                                }
                                item {
                                    Card(colors = CardDefaults.cardColors(containerColor = CardBg),
                                        shape = RoundedCornerShape(17.dp)) {
                                        Column(Modifier.fillMaxWidth().padding(15.dp)) {
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                Text("SCAN COVERAGE", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                                Spacer(Modifier.weight(1f))
                                                Text(if (scanning) "SCANNING" else "INVENTORY DONE",
                                                    color = if (scanning) Orange else Green, fontSize = 10.sp)
                                            }
                                            Spacer(Modifier.height(10.dp))
                                            LinearProgressIndicator(
                                                progress = { if (scanning) 0.5f else if (apps.isEmpty()) 0f else 1f },
                                                modifier = Modifier.fillMaxWidth().height(6.dp),
                                                color = Green, trackColor = Raised)
                                            Spacer(Modifier.height(9.dp))
                                            Text("${apps.size} / ${apps.size} apps inventoried",
                                                color = Grey, fontSize = 12.sp)
                                            Spacer(Modifier.height(9.dp))
                                            Text("CHECKED", color = Green, fontWeight = FontWeight.Bold, fontSize = 10.sp)
                                            Text("App identity • version • signer • permissions • exported components • debug flag",
                                                color = Grey, fontSize = 11.sp)
                                            Spacer(Modifier.height(8.dp))
                                            Text("NOT TESTED", color = Orange, fontWeight = FontWeight.Bold, fontSize = 10.sp)
                                            Text("Live behavior • malware activity • network/API • billing integrity • exploit confirmation",
                                                color = Grey, fontSize = 11.sp)
                                        }
                                    }
                                }
                                item {
                                    Card(colors = CardDefaults.cardColors(containerColor = CardBg),
                                        shape = RoundedCornerShape(16.dp)) {
                                        Column(Modifier.fillMaxWidth().padding(15.dp)) {
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                Text("SHIZUKU / ADB BRIDGE", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                                Spacer(Modifier.weight(1f))
                                                Text(if (bridge.startsWith("Connected")) "CONNECTED" else "OFFLINE",
                                                    color = if (bridge.startsWith("Connected")) Green else Orange, fontSize = 10.sp)
                                            }
                                            Spacer(Modifier.height(7.dp))
                                            Text(bridge, color = Grey, fontSize = 12.sp)
                                            Row {
                                                TextButton(onClick = {
                                                    try {
                                                        if (!Shizuku.pingBinder()) bridge = "Start Shizuku service first"
                                                        else if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                                                            Shizuku.requestPermission(4102); bridge = "Permission request sent"
                                                        } else bridgeStatus()
                                                    } catch (e: Exception) { bridge = "Error: ${e.message}" }
                                                }) { Text("Grant / Check") }
                                                TextButton(onClick = { bridgeStatus() }) { Text("Refresh") }
                                            }
                                        }
                                    }
                                }
                                item {
                                    Card(colors = CardDefaults.cardColors(containerColor = CardBg),
                                        shape = RoundedCornerShape(16.dp)) {
                                        Column(Modifier.fillMaxWidth().padding(15.dp)) {
                                            Text("SCAN CONTROLS", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                            Text("Refresh the local, read-only installed-app inventory.",
                                                color = Grey, fontSize = 11.sp, modifier = Modifier.padding(top = 5.dp))
                                            Button(onClick = { scan(); bridgeStatus() }, enabled = !scanning,
                                                modifier = Modifier.fillMaxWidth().padding(top = 10.dp)) {
                                                Icon(Icons.Default.Refresh, null)
                                                Spacer(Modifier.width(8.dp))
                                                Text(if (scanning) "Scanning…" else "Refresh app inventory")
                                            }
                                            Text(scanTime, color = Grey, fontSize = 10.sp,
                                                modifier = Modifier.padding(top = 8.dp))
                                        }
                                    }
                                }
                                item {
                                    Text("ABOUT THESE RESULTS", color = Green, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                                    Text("Review flags need manual review; they are not proof an app is hacked. Current checks include package metadata, APK archive/text-pattern scanning, SHA-256 hashing, signer comparison and a manual one-request HTTPS/TLS check. Runtime malware behavior, full API crawling, billing sandbox validation and exploit confirmation are not implemented.",
                                        color = Grey, fontSize = 11.sp)
                                }
                            }
                            else -> {
                                Text("App testing lab", fontSize = 22.sp, fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(top = 8.dp))
                                Text("Installed apps or APK files supplied by an authorized owner",
                                    color = Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 3.dp))
                                OutlinedButton(onClick = { showAuthorization = true },
                                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                                    Icon(Icons.Default.Shield, null)
                                    Spacer(Modifier.width(8.dp))
                                    Text("Test a friend's APK file")
                                }
                                if (importMessage.isNotBlank()) {
                                    Text(importMessage, color = Grey, fontSize = 10.sp,
                                        modifier = Modifier.padding(bottom = 5.dp))
                                }
                                Card(modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
                                    colors = CardDefaults.cardColors(containerColor = CardBg),
                                    shape = RoundedCornerShape(17.dp)) {
                                    Column(Modifier.fillMaxWidth().padding(13.dp)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Column(Modifier.weight(1f)) {
                                                Text("DEVICE APP INVENTORY", color = Grey, fontSize = 9.sp,
                                                    fontWeight = FontWeight.Bold, letterSpacing = 1.2.sp)
                                                Text("${apps.size} apps discovered", fontSize = 20.sp,
                                                    fontWeight = FontWeight.ExtraBold)
                                            }
                                            Surface(color = Green.copy(alpha = .13f), shape = RoundedCornerShape(30.dp)) {
                                                Text("LOCAL • OFFLINE", color = Green, fontSize = 8.sp,
                                                    fontWeight = FontWeight.Bold,
                                                    modifier = Modifier.padding(horizontal = 9.dp, vertical = 6.dp))
                                            }
                                        }
                                        Spacer(Modifier.height(10.dp))
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            Metric("NEEDS REVIEW", review.toString(), "Metadata flags", Orange, Modifier.weight(1f))
                                            Metric("DEBUG BUILDS", high.toString(), "Debuggable flag", Red, Modifier.weight(1f))
                                        }
                                    }
                                }
                                Text("Installed applications", fontSize = 16.sp, fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(top = 10.dp))
                                Text("${shown.size} apps • Tap an app to inspect its metadata",
                                    color = Grey, fontSize = 11.sp, modifier = Modifier.padding(top = 3.dp, bottom = 10.dp))
                                OutlinedTextField(value = query, onValueChange = { query = it },
                                    modifier = Modifier.fillMaxWidth(), singleLine = true,
                                    placeholder = { Text("Search app or package…") },
                                    leadingIcon = { Icon(Icons.Default.Search, null) },
                                    shape = RoundedCornerShape(14.dp))
                                Spacer(Modifier.height(8.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(5.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    listOf("ALL", "REVIEW", "USER", "SYSTEM").forEach {
                                        FilterChip(selected = filter == it, onClick = { filter = it },
                                            label = { Text(it, fontSize = 9.sp) })
                                    }
                                    Spacer(Modifier.weight(1f))
                                    TextButton(onClick = { riskFirst = !riskFirst },
                                        contentPadding = PaddingValues(horizontal = 6.dp, vertical = 0.dp)) {
                                        Text(if (riskFirst) "RISK FIRST" else "A–Z",
                                            color = Green, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                                    }
                                }
                                Spacer(Modifier.height(5.dp))
                                if (scanning && apps.isEmpty()) {
                                    Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                                        CircularProgressIndicator(color = Green)
                                    }
                                } else {
                                    LazyColumn(
                                        modifier = Modifier.weight(1f).fillMaxWidth(),
                                        contentPadding = PaddingValues(top = 4.dp, bottom = 24.dp)
                                    ) {
                                        items(shown, key = { it.pkg }) { app ->
                                            AppItem(app) { selected = app }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun Metric(label: String, value: String, note: String, tint: Color, modifier: Modifier) {
    Card(modifier, colors = CardDefaults.cardColors(containerColor = CardBg),
        shape = RoundedCornerShape(15.dp)) {
        Column(Modifier.padding(10.dp)) {
            Text(label, color = Grey, fontSize = 9.sp, fontWeight = FontWeight.Bold)
            Text(value, color = tint, fontSize = 24.sp, fontWeight = FontWeight.ExtraBold)
            Text(note, color = Grey, fontSize = 9.sp, maxLines = 1)
        }
    }
}

@Composable
private fun Status(status: String) {
    val c = when (status) { "HIGH RISK" -> Red; "REVIEW" -> Orange; else -> Green }
    Surface(color = c.copy(alpha = .13f), shape = RoundedCornerShape(40.dp)) {
        Text(status, color = c, fontSize = 8.sp, fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp))
    }
}

@Composable
private fun AppItem(app: AppRow, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = CardBg),
        shape = RoundedCornerShape(17.dp)
    ) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Surface(Modifier.size(50.dp), color = Raised, shape = RoundedCornerShape(14.dp)) {
                Box(contentAlignment = Alignment.Center) {
                    if (app.icon != null) Image(app.icon.asImageBitmap(), null, Modifier.size(42.dp))
                    else Text(app.name.take(1).uppercase(), color = Green, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                }
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(app.name, fontSize = 14.sp, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(app.pkg, color = Grey, fontSize = 9.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text((if (app.system) "SYSTEM" else "USER APP") + "  •  VERSION " + app.version,
                    color = Grey.copy(alpha = 0.85f), fontSize = 8.sp, modifier = Modifier.padding(top = 3.dp))
                Spacer(Modifier.height(6.dp))
                Status(app.status)
            }
            Text("›", color = Green, fontSize = 26.sp, fontWeight = FontWeight.Light)
        }
    }
}

private data class WorkspaceFeature(
    val title: String,
    val description: String,
    val state: String,
    val available: Boolean = false
)
private data class WorkspaceCategory(
    val title: String,
    val subtitle: String,
    val features: List<WorkspaceFeature>
)

private fun subcategoryFor(category: String, feature: String): String {
    return when (category) {
        "Security audit" -> when (feature) {
            "Signer & integrity", "DEX & native libraries" -> "Code & signing"
            "Debug & exported components", "Cleartext traffic policy", "Malware behavior" -> "Manifest & runtime exposure"
            else -> "Security overview"
        }
        "Permissions & privacy" -> if (feature.contains("Permission")) "Permissions" else "Privacy & data access"
        "Network & connectivity" -> when (feature) {
            "API endpoints", "TLS & certificates" -> "API & transport security"
            else -> "Traffic & connectivity"
        }
        "Storage & data" -> if (feature.contains("Backup") || feature.contains("database", true)) "Data protection" else "Storage inspection"
        "Billing & subscriptions" -> if (feature.contains("License")) "Entitlement integrity" else "Purchases & virtual goods"
        "Appearance & identity" -> if (feature.contains("Icon") || feature.contains("Branding")) "Brand identity" else "Display customization"
        "App actions" -> if (feature.contains("APK")) "Package installation" else "Device actions & reports"
        else -> "General"
    }
}

private fun runFeatureAudit(app: AppRow, feature: WorkspaceFeature): List<String> {
    return when (feature.title) {
        "Security overview" -> buildList {
            add("Local package metadata reviewed for " + app.name + ".")
            add("Inventory state: " + app.status + ".")
            if (app.findings.isEmpty()) add("No configured metadata review flags were raised.") else app.findings.forEach { add("Review signal: " + it) }
            add("Static metadata review only; this is not a malware verdict.")
        }
        "Signer & integrity" -> listOf("Signer certificate SHA-256: " + app.signer, "APK file SHA-256 is included in the archive inventory.", "Compare the signer fingerprint with a trusted release record; matching signer identity is not a malware verdict.")
        "DEX & native libraries" -> app.archiveInventory.ifEmpty { listOf("APK archive inventory is unavailable.") }
        "Compare APK builds" -> listOf("Choose another APK to compare package identity, version, signer fingerprint, requested permissions, exported components and file hash.")
        "Debug & exported components" -> buildList {
            add("Debuggable flag: " + app.debug + ".")
            add("Exported component count: " + app.exportedComponents.size + ".")
            app.exportedComponents.forEach { add(it) }
            add("Exported components need access-control review; exported alone is not proof of vulnerability.")
        }
        "API endpoints", "TLS & certificates" -> listOf("Enter one HTTPS endpoint you own or are authorized to test.", "The check sends a single HEAD request, does not follow redirects, and does not send credentials or a request body.", "This checks the endpoint response, not every API route used by the app.")
        "Cleartext traffic policy" -> app.findings.filter { it.contains("Cleartext", true) }.ifEmpty { listOf("No cleartext manifest flag was raised. Binary XML and runtime traffic remain untested.") }
        "Permission inventory" -> listOf("Declared permissions: " + app.permissions.size) + app.permissions
        "Sensitive permissions" -> {
            val sensitive = app.permissions.filter { p -> listOf("CAMERA", "RECORD_AUDIO", "LOCATION", "CONTACTS", "SMS", "PHONE", "CALENDAR", "BODY_SENSORS").any { p.contains(it) } }
            listOf("Sensitive permission candidates: " + sensitive.size) + sensitive
        }
        "Runtime permission grants" -> if (app.installer == "Imported APK • not installed") listOf("Runtime grants are unavailable for an APK that is not installed.") else app.permissions.map { p -> (if (app.grantedPermissions.contains(p)) "GRANTED • " else "NOT GRANTED • ") + p }.ifEmpty { listOf("No declared permissions were reported.") }
        "Backup exposure" -> listOf(app.findings.firstOrNull { it.contains("backup", true) } ?: "No backup-enabled metadata flag was raised.", "Backup rules and backed-up data are not inspected.")
        "Display name" -> listOf("Name preview is available inside this workspace only.", "The installed launcher label is unchanged.")
        "Icon concept" -> listOf("Icon concept is design-only; the installed app icon is unchanged.")
        "Export audit summary" -> listOf("Audit report assembled from current static inventory.", "Use Share audit report or Save PDF report to export it.")
        "Open app" -> listOf(if (app.installer == "Imported APK • not installed") "Imported APK is not installed." else "Use Launch app to open the installed app.")
        "Open system app settings" -> listOf(if (app.installer == "Imported APK • not installed") "Imported APK has no Android settings page on this device." else "Use Open Android app settings to view system controls.")
        "Install / reinstall APK" -> listOf("Package Installer opens after you press the install button.", "Android displays its own confirmation and installation result.")
        "Create APK backup" -> listOf("Export a copy of the available APK source using Android document picker.", "Split APK applications may need a complete package set; this exports only the selected base APK.")
        else -> listOf("Automated test engine is not implemented for this feature yet.", "No test was run and no pass/fail result is claimed.")
    }
}
@Composable
private fun Detail(app: AppRow, onBack: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val installed = app.installer != "Imported APK • not installed"
    var pendingPdfText by remember { mutableStateOf("") }
    var installMessage by remember { mutableStateOf("") }
    var backupMessage by remember { mutableStateOf("") }
    var comparisonMessage by remember { mutableStateOf("") }
    var storageResult by remember { mutableStateOf("") }
    val backupLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
        if (uri != null) {
            try {
                val sources = app.apkPaths.ifEmpty { listOfNotNull(app.apkPath) }.map { File(it) }.filter { it.isFile }
                if (sources.isEmpty()) throw IllegalStateException("No APK source files are available")
                context.contentResolver.openOutputStream(uri)?.use { raw ->
                    ZipOutputStream(raw).use { zipOut ->
                        sources.forEachIndexed { index, source ->
                            val entryName = if (sources.size == 1) source.name else "apk-set/" + index.toString().padStart(2, '0') + "-" + source.name
                            zipOut.putNextEntry(ZipEntry(entryName))
                            source.inputStream().use { input -> input.copyTo(zipOut) }
                            zipOut.closeEntry()
                        }
                    }
                } ?: throw IllegalStateException("Could not open destination")
                backupMessage = "APK backup bundle exported: ${sources.size} APK file(s)."
            } catch (e: Exception) { backupMessage = "Backup failed: ${e.message}" }
        } else backupMessage = "Backup cancelled."
    }
    val installScope = rememberCoroutineScope()
    val comparisonPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            installScope.launch {
                comparisonMessage = "Reading comparison APK…"
                try {
                    val report = withContext(Dispatchers.IO) {
                        val comparisonFile = File(context.cacheDir, "compare-" + System.currentTimeMillis() + ".apk")
                        context.contentResolver.openInputStream(uri)?.use { input ->
                            comparisonFile.outputStream().use { output -> input.copyTo(output) }
                        } ?: throw IllegalStateException("Could not read selected APK")
                        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or
                            PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or
                            (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else 0)
                        val other = context.packageManager.getPackageArchiveInfo(comparisonFile.absolutePath, flags)
                            ?: throw IllegalArgumentException("Selected file is not a readable APK")
                        val otherSigner = if (Build.VERSION.SDK_INT >= 28) {
                            other.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()?.let { bytes ->
                                MessageDigest.getInstance("SHA-256").digest(bytes).joinToString(":") { "%02X".format(it) }
                            } ?: "Unavailable"
                        } else "Unavailable on this Android version"
                        val otherPermissions = other.requestedPermissions?.toSet() ?: emptySet()
                        val currentPermissions = app.permissions.toSet()
                        val exportedCount = (other.activities?.count { it.exported } ?: 0) +
                            (other.services?.count { it.exported } ?: 0) +
                            (other.receivers?.count { it.exported } ?: 0) +
                            (other.providers?.count { it.exported } ?: 0)
                        val hash = inspectApkArchive(comparisonFile.absolutePath).firstOrNull { it.startsWith("APK SHA-256:") } ?: "APK hash unavailable"
                        buildList {
                            add("Current app: ${app.pkg} • version ${app.version}")
                            add("Selected APK: ${other.packageName} • version ${other.versionName ?: "Unknown"}")
                            add("Package identity: " + if (other.packageName == app.pkg) "MATCH" else "DIFFERENT PACKAGE")
                            add("Signer: " + if (otherSigner == app.signer && otherSigner != "Unavailable") "MATCH" else "DIFFERENT / UNAVAILABLE")
                            add("Selected signer SHA-256: $otherSigner")
                            add("New requested permissions: " + (otherPermissions - currentPermissions).size)
                            (otherPermissions - currentPermissions).sorted().take(30).forEach { add("ADDED PERMISSION • $it") }
                            add("Removed requested permissions: " + (currentPermissions - otherPermissions).size)
                            (currentPermissions - otherPermissions).sorted().take(30).forEach { add("REMOVED PERMISSION • $it") }
                            add("Exported components: current ${app.exported} • selected $exportedCount")
                            add(hash)
                            add("Static comparison only; compare official release lineage before replacing an installed app.")
                        }.joinToString("\n")
                    }
                    comparisonMessage = report
                } catch (e: Exception) {
                    comparisonMessage = "Comparison failed: ${e.message ?: e.javaClass.simpleName}"
                }
            }
        } else comparisonMessage = "Comparison cancelled."
    }
    val installLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        installMessage = when (result.resultCode) {
            android.app.Activity.RESULT_OK -> "Installer reported success. Refresh the app inventory to confirm."
            android.app.Activity.RESULT_CANCELED -> "Installer was cancelled or returned no completion result. Check the installed-app list."
            else -> "Installer returned code " + result.resultCode + ". Check the installed-app list."
        }
    }
    val pdfLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        if (uri != null) {
            try {
                val pdf = PdfDocument()
                val paint = Paint().apply { textSize = 10f; isAntiAlias = true }
                val lines = pendingPdfText.lines()
                var pageNumber = 1
                var index = 0
                while (index < lines.size) {
                    val page = pdf.startPage(PdfDocument.PageInfo.Builder(595, 842, pageNumber).create())
                    var y = 42f
                    while (index < lines.size && y < 810f) {
                        val line = lines[index].take(105)
                        page.canvas.drawText(line, 36f, y, paint)
                        y += 15f
                        index++
                    }
                    pdf.finishPage(page)
                    pageNumber++
                }
                context.contentResolver.openOutputStream(uri)?.use { pdf.writeTo(it) }
                pdf.close()
            } catch (_: Exception) { }
        }
    }
    fun openInstalledApp() {
        if (!installed) return
        val launch = context.packageManager.getLaunchIntentForPackage(app.pkg) ?: return
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(launch)
    }
    fun openAppSettings() {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + app.pkg))
        context.startActivity(intent)
    }
    fun buildAuditReport(): String = buildString {
            appendLine("OMNI CYBER LAB — APP AUDIT")
            appendLine("App: " + app.name)
            appendLine("Package: " + app.pkg)
            appendLine("Version: " + app.version)
            appendLine("Target SDK: " + app.targetSdk)
            appendLine("Installer: " + app.installer)
            appendLine("Debuggable: " + app.debug)
            appendLine("Exported components: " + app.exported)
            appendLine("APK archive inventory:")
            app.archiveInventory.forEach { appendLine("- " + it) }
            appendLine("Exported component inventory:")
            if (app.exportedComponents.isEmpty()) appendLine("- None reported by package metadata")
            else app.exportedComponents.forEach { appendLine("- " + it) }
            appendLine("Manifest review signals:")
            val manifestSignals = app.findings.filter { it.contains("backup") || it.contains("Cleartext") }
            if (manifestSignals.isEmpty()) appendLine("- No backup/cleartext metadata flags raised")
            else manifestSignals.forEach { appendLine("- " + it) }
            appendLine("Signer SHA-256: " + app.signer)
            appendLine("Requested permissions:")
            app.permissions.forEach { permission ->
                val grant = if (installed) {
                    if (app.grantedPermissions.contains(permission)) "GRANTED" else "NOT GRANTED"
                } else "NOT AVAILABLE FOR UNINSTALLED APK"
                appendLine("- " + permission + " [" + grant + "]")
            }
            appendLine("Structured findings and suggested remediation:")
            if (app.findings.isEmpty()) appendLine("- No basic metadata flags raised")
            else app.findings.forEach { finding ->
                val (severity, remediation) = classifyFinding(finding)
                appendLine("- [$severity] $finding")
                appendLine("  Recommendation: $remediation")
            }
            appendLine("Framework note: MASVS labels are guidance mappings, not a formal compliance result. Severity requires validation and evidence.")
            appendLine("Static metadata only; not a malware verdict or full penetration test.")
    }
    fun exportAudit() {
        val report = buildAuditReport()
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "OMNI CYBER LAB audit — " + app.name)
            putExtra(Intent.EXTRA_TEXT, report)
        }
        context.startActivity(Intent.createChooser(send, "Export audit report"))
    }
    val categories = remember(app) {
        listOf(
            WorkspaceCategory("Security audit", "App integrity and risk indicators", listOf(
                WorkspaceFeature("Security overview", "Review the metadata checks and findings for this app.", app.status, true),
                WorkspaceFeature("Signer & integrity", "Inspect the signing certificate fingerprint and compare it with a trusted release fingerprint.", if (app.signer == "Unavailable") "UNAVAILABLE" else "READY • FINGERPRINT", true),
                WorkspaceFeature("DEX & native libraries", "Inventory DEX/native files and scan bounded DEX strings for URLs, credential-like strings and behavior markers.", if (app.archiveInventory.isEmpty()) "NOT AVAILABLE" else "ARCHIVE + DEX TRIAGE", app.archiveInventory.isNotEmpty()),
                WorkspaceFeature("Compare APK builds", "Compare another APK against this app: package, version, signer, permissions and exported components.", "READY • SELECT APK", true),
                WorkspaceFeature("Debug & exported components", "Review debug flags and externally reachable components.", if (app.debug || app.exported > 0) "REVIEW" else "CHECKED", true),
                WorkspaceFeature("Cleartext traffic policy", "Check the manifest cleartext-traffic setting.", if (app.findings.any { it.contains("Cleartext") }) "REVIEW" else "NO FLAG", true),
                WorkspaceFeature("Malware behavior", "Runtime behavior and malware detection are not implemented in this build.", "NOT IMPLEMENTED")
            )),
            WorkspaceCategory("Permissions & privacy", "Understand what the app requests", listOf(
                WorkspaceFeature("Permission inventory", "View every permission declared by this app.", "${app.permissions.size} FOUND", true),
                WorkspaceFeature("Sensitive permissions", "Review camera, microphone, location, contacts and SMS requests.", if (app.findings.any { it.contains("Sensitive") }) "REVIEW" else "BASIC CHECK", true),
                WorkspaceFeature("Runtime permission grants", "Check declared permissions against Android's current grant state.", if (installed) "LIVE CHECK" else "APK ONLY", installed),
                WorkspaceFeature("Private app data", "Private sandbox contents are not accessible to this inventory tool.", "NOT ACCESSIBLE"),
                WorkspaceFeature("Privacy review", "A full privacy policy and data-flow review is not implemented.", "NOT IMPLEMENTED")
            )),
            WorkspaceCategory("Network & connectivity", "Network-facing security checks", listOf(
                WorkspaceFeature("Network traffic", "No packet capture or traffic inspection is active.", "NOT TESTED"),
                WorkspaceFeature("API endpoints", "Run a one-request HTTPS endpoint review against a URL supplied by the app owner.", "READY • MANUAL URL", true),
                WorkspaceFeature("TLS & certificates", "Check TLS negotiation, peer certificate validity and selected response security headers.", "READY • MANUAL URL", true),
                WorkspaceFeature("Offline behavior", "Runtime offline behavior has not been tested.", "NOT TESTED")
            )),
            WorkspaceCategory("Storage & data", "App storage and data handling", listOf(
                WorkspaceFeature("Storage footprint", "Measure installed app APK, data and cache sizes after you grant Android Usage Access.", "REQUIRES USAGE ACCESS", installed),
                WorkspaceFeature("Backup exposure", "Review the manifest backup-enabled flag; backup rules and actual data exposure still need deeper testing.", if (app.findings.any { it.contains("backup") }) "REVIEW" else "NO FLAG", true),
                WorkspaceFeature("Local database", "Private databases remain inside the app sandbox.", "NOT ACCESSIBLE")
            )),
            WorkspaceCategory("Billing & subscriptions", "Review purchases without bypassing them", listOf(
                WorkspaceFeature("In-app products", "Product catalog and billing integrity are not inspected in this build.", "NOT TESTED"),
                WorkspaceFeature("Subscriptions", "Subscription status must be checked through the official store/account.", "NOT CONNECTED"),
                WorkspaceFeature("Coins, gold & virtual items", "Virtual currency balances and purchase records are not read.", "NOT ACCESSIBLE"),
                WorkspaceFeature("License integrity", "No license bypass or payment unlocking. Verification is not implemented.", "NOT IMPLEMENTED")
            )),
            WorkspaceCategory("Appearance & identity", "Plan a custom app presentation", listOf(
                WorkspaceFeature("Display name", "Preview a custom label inside this workspace. Android's installed app label is not changed.", "PREVIEW ONLY", true),
                WorkspaceFeature("Icon concept", "Preview a visual direction for a custom icon; original app icon stays unchanged.", "PREVIEW ONLY", true),
                WorkspaceFeature("Theme & colors", "Choose a theme concept for a companion design.", "PLANNING ONLY"),
                WorkspaceFeature("Branding package", "Plan name, icon, colors and splash-screen assets for an app you own.", "PLANNING ONLY")
            )),
            WorkspaceCategory("App actions", "Safe device-level actions", listOf(
                WorkspaceFeature("Open app", if (installed) "Launch this installed app." else "Imported APK is not installed; launch is unavailable.", if (installed) "AVAILABLE" else "NOT AVAILABLE", installed),
                WorkspaceFeature("Open system app settings", "View Android's official settings page for this app.", if (installed) "AVAILABLE" else "NOT AVAILABLE FOR APK", installed),
                WorkspaceFeature("Export audit summary", "Share a readable metadata audit report.", "AVAILABLE", true),
                WorkspaceFeature("Uninstall / disable", "Use Android system controls; protected system apps may not allow changes.", "SYSTEM CONTROL"),
                WorkspaceFeature("Install / reinstall APK", "Open Android Package Installer with this APK. Android confirmation is always required.", if (app.apkPath.isNullOrBlank()) "APK NOT AVAILABLE" else if (installed) "REINSTALL / UPDATE" else "INSTALL APK", !app.apkPath.isNullOrBlank()),
                WorkspaceFeature("Create APK backup", "Export the base APK and available split APK files together as a ZIP backup bundle.", if (app.apkPaths.isEmpty() && app.apkPath.isNullOrBlank()) "SOURCE UNAVAILABLE" else "READY • APK SET", !app.apkPaths.isEmpty() || !app.apkPath.isNullOrBlank())
            ))
        )
    }
    var category by remember { mutableStateOf<WorkspaceCategory?>(null) }
    var subcategory by remember { mutableStateOf<String?>(null) }
    var feature by remember { mutableStateOf<WorkspaceFeature?>(null) }
    var featureResults by remember { mutableStateOf(emptyList<String>()) }
    var alias by remember(app.pkg) { mutableStateOf(app.name) }
    var trustedSigner by remember(app.pkg) { mutableStateOf("") }
    var signerCheckResult by remember(app.pkg) { mutableStateOf("") }
    var showAliasPreview by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = {
                when {
                    feature != null -> feature = null
                    subcategory != null -> subcategory = null
                    category != null -> category = null
                    else -> onBack()
                }
            }) { Icon(Icons.Default.ArrowBack, "Back") }
            Column(Modifier.weight(1f)) {
                Text("APP WORKSPACE", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                Text(
                    when {
                        feature != null -> feature!!.title
                        subcategory != null -> subcategory!!
                        category != null -> category!!.title
                        else -> "Categories & tools"
                    }, color = Grey, fontSize = 10.sp
                )
            }
            Status(app.status)
        }
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            item {
                Card(colors = CardDefaults.cardColors(containerColor = CardBg),
                    shape = RoundedCornerShape(18.dp)) {
                    Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        if (app.icon != null) Image(app.icon.asImageBitmap(), null, Modifier.size(54.dp))
                        else Surface(Modifier.size(54.dp), color = Raised, shape = RoundedCornerShape(14.dp)) {
                            Box(contentAlignment = Alignment.Center) { Text(app.name.take(1), color = Green) }
                        }
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(app.name, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                            Text(app.pkg, color = Grey, fontSize = 9.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text("v${app.version} • " + if (app.system) "System app" else "User app",
                                color = Grey, fontSize = 9.sp)
                        }
                    }
                }
            }
            if (feature != null) {
                item {
                    val current = feature!!
                    Card(colors = CardDefaults.cardColors(containerColor = CardBg),
                        shape = RoundedCornerShape(17.dp)) {
                        Column(Modifier.fillMaxWidth().padding(15.dp)) {
                            Text(current.title, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                            Text(current.description, color = Grey, fontSize = 12.sp,
                                modifier = Modifier.padding(top = 7.dp))
                            Spacer(Modifier.height(12.dp))
                            Status(if (current.state == "AVAILABLE" || current.state == "CHECKED" || current.state == "LIVE CHECK") "CHECKED" else "REVIEW")
                            Text("STATUS: ${current.state}", color = Green, fontSize = 10.sp,
                                fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 10.dp))
                            if (featureResults.isNotEmpty()) {
                                Text("AUTOMATED RESULT", color = Green, fontWeight = FontWeight.Bold, fontSize = 11.sp, modifier = Modifier.padding(top = 12.dp))
                                featureResults.forEach { result ->
                                    Text("• $result", color = Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 5.dp))
                                }
                            }
                            if (current.title == "Signer & integrity") {
                                Text("CURRENT SIGNER SHA-256", color = Green, fontSize = 10.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 12.dp))
                                Text(app.signer, color = Grey, fontSize = 9.sp)
                                OutlinedTextField(value = trustedSigner, onValueChange = { trustedSigner = it }, modifier = Modifier.fillMaxWidth().padding(top = 10.dp), label = { Text("Trusted release SHA-256 fingerprint") }, placeholder = { Text("Paste known fingerprint") })
                                Button(onClick = {
                                    val expected = trustedSigner.filter { it.isLetterOrDigit() }.uppercase()
                                    val actual = app.signer.filter { it.isLetterOrDigit() }.uppercase()
                                    signerCheckResult = when {
                                        expected.length != 64 -> "Enter a complete 64-character SHA-256 fingerprint."
                                        app.signer == "Unavailable" -> "Signer fingerprint is unavailable for this package."
                                        expected == actual -> "MATCH • signer fingerprint matches your trusted value."
                                        else -> "MISMATCH • signer differs from the trusted value; verify the source and update history."
                                    }
                                }, enabled = trustedSigner.isNotBlank(), modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Compare trusted fingerprint") }
                                if (signerCheckResult.isNotBlank()) Text(signerCheckResult, color = if (signerCheckResult.startsWith("MATCH")) Green else Orange, fontSize = 10.sp, modifier = Modifier.padding(top = 8.dp))
                            }
                            if (current.title == "Storage footprint") {
                                Button(onClick = {
                                    try {
                                        val ops = context.getSystemService(AppOpsManager::class.java)
                                        val mode = ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
                                        if (mode != AppOpsManager.MODE_ALLOWED) {
                                            storageResult = "Android Usage Access is required. Enable OMNI CYBER LAB, return here and measure again."
                                            context.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
                                        } else {
                                            installScope.launch {
                                                storageResult = "Measuring app storage…"
                                                storageResult = withContext(Dispatchers.IO) {
                                                    try {
                                                        val statsManager = context.getSystemService(StorageStatsManager::class.java)
                                                        val stats = statsManager.queryStatsForPackage(StorageManager.UUID_DEFAULT, app.pkg, Process.myUserHandle())
                                                        fun size(value: Long): String {
                                                            val mb = value / (1024.0 * 1024.0)
                                                            return if (mb >= 1024) "%.2f GB".format(mb / 1024.0) else "%.1f MB".format(mb)
                                                        }
                                                        "APK/app code: ${size(stats.appBytes)}\nUser data: ${size(stats.dataBytes)}\nCache: ${size(stats.cacheBytes)}\nTotal: ${size(stats.appBytes + stats.dataBytes + stats.cacheBytes)}"
                                                    } catch (e: Exception) {
                                                        "Storage query unavailable: ${e.message ?: e.javaClass.simpleName}"
                                                    }
                                                }
                                            }
                                        }
                                    } catch (e: Exception) { storageResult = "Could not check Usage Access: ${e.message}" }
                                }, enabled = installed, modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
                                    Text("Measure app storage")
                                }
                                if (storageResult.isNotBlank()) Text(storageResult, color = Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 9.dp))
                                Text("Android controls this data. It reports package storage totals; it does not expose the app's private database contents.", color = Orange, fontSize = 9.sp, modifier = Modifier.padding(top = 8.dp))
                            }
                            if (current.title == "Compare APK builds") {
                                Button(onClick = { comparisonPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) },
                                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
                                    Text("Choose comparison APK")
                                }
                                if (comparisonMessage.isNotBlank()) {
                                    Text(comparisonMessage, color = Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 9.dp))
                                }
                                Text("Comparison is static metadata only. It does not run either APK or prove that one build is safe.", color = Orange, fontSize = 9.sp, modifier = Modifier.padding(top = 8.dp))
                            }
                            if (current.title == "API endpoints" || current.title == "TLS & certificates") {
                                EndpointAuditPanel()
                            }
                            if (current.title == "Install / reinstall APK") {
                                Button(
                                    onClick = {
                                        val source = app.apkPath
                                        if (source.isNullOrBlank()) {
                                            installMessage = "No APK file is available for this app."
                                        } else {
                                            installMessage = "Preparing APK for Android Package Installer…"
                                            installScope.launch {
                                                try {
                                                    val prepared = withContext(Dispatchers.IO) {
                                                        val sourceFile = File(source)
                                                        if (!sourceFile.exists()) throw IllegalStateException("APK source file is no longer available")
                                                        val folder = File(context.cacheDir, "install")
                                                        if (!folder.exists() && !folder.mkdirs()) throw IllegalStateException("Cannot create install cache")
                                                        val safeName = app.pkg.replace(Regex("[^A-Za-z0-9_.-]"), "_")
                                                        val target = File(folder, safeName + ".apk")
                                                        sourceFile.copyTo(target, overwrite = true)
                                                        target
                                                    }
                                                    val uri = FileProvider.getUriForFile(context, context.packageName + ".files", prepared)
                                                    val intent = Intent(Intent.ACTION_VIEW).apply {
                                                        setDataAndType(uri, "application/vnd.android.package-archive")
                                                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                                    }
                                                    installLauncher.launch(intent)
                                                    installMessage = "Android installer opened. Review the app name and package, then confirm on the system screen."
                                                } catch (e: Exception) {
                                                    installMessage = "Could not open installer: " + e.message
                                                }
                                            }
                                        }
                                    },
                                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp)
                                ) {
                                    Text(if (installed) "Reinstall / Update APK" else "Install APK")
                                }
                                Text("Android will ask for confirmation. Silent installation and security prompts are not bypassed. A split APK app may require its complete split package set.", color = Orange, fontSize = 10.sp, modifier = Modifier.padding(top = 7.dp))
                                if (installMessage.isNotBlank()) Text(installMessage, color = Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 8.dp))
                            } else if (current.title == "Create APK backup") {
                                Button(onClick = { backupLauncher.launch(app.pkg.substringAfterLast(".") + "-" + app.version + "-apk-set.zip") }, enabled = !app.apkPath.isNullOrBlank(), modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
                                    Text("Export APK set backup (.zip)")
                                }
                                if (backupMessage.isNotBlank()) Text(backupMessage, color = if (backupMessage.startsWith("APK backup exported")) Green else Orange, fontSize = 10.sp, modifier = Modifier.padding(top = 8.dp))
                                Text("Exports available base/split APK files only. It does not back up private app data. Restore of split sets needs a compatible installer or authorized ADB/Shizuku workflow.", color = Orange, fontSize = 9.sp, modifier = Modifier.padding(top = 8.dp))
                            } else if (current.title == "DEX & native libraries") {
                                Text("APK archive inventory", color = Green, fontWeight = FontWeight.Bold, fontSize = 11.sp, modifier = Modifier.padding(top = 12.dp))
                                app.archiveInventory.forEach { line -> Text("• $line", color = Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 5.dp)) }
                                Text("The archive scanner samples limited text/config files for credential-like patterns and redacts matched values. It does not decompile DEX, inspect binary resources, audit native code or prove malware absence.", color = Orange, fontSize = 9.sp, modifier = Modifier.padding(top = 8.dp))
                            } else if (current.title == "Debug & exported components") {
                                Text("${app.exportedComponents.size} exported components found", color = Green, fontWeight = FontWeight.Bold, fontSize = 11.sp, modifier = Modifier.padding(top = 12.dp))
                                if (app.exportedComponents.isEmpty()) Text("No exported components were reported by package metadata.", color = Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 6.dp))
                                else app.exportedComponents.forEach { component -> Text("• $component", color = Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 6.dp)) }
                                Text("Exported does not automatically mean vulnerable. Verify intent filters, caller permissions, input validation and sensitive actions during an authorized runtime test.", color = Orange, fontSize = 9.sp, modifier = Modifier.padding(top = 8.dp))
                            } else if (current.title == "Permission inventory" || current.title == "Sensitive permissions" || current.title == "Runtime permission grants") {
                                val visiblePermissions = if (current.title == "Sensitive permissions" || current.title == "Runtime permission grants") {
                                    app.permissions.filter { p -> listOf("CAMERA", "RECORD_AUDIO", "LOCATION", "CONTACTS", "SMS", "PHONE", "CALENDAR", "BODY_SENSORS").any { p.contains(it) } }
                                } else app.permissions
                                Text("${visiblePermissions.size} permission entries", color = Green,
                                    fontWeight = FontWeight.Bold, fontSize = 11.sp,
                                    modifier = Modifier.padding(top = 12.dp))
                                if (visiblePermissions.isEmpty()) {
                                    Text("No matching declared permissions were found in the package metadata.",
                                        color = Grey, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
                                } else {
                                    visiblePermissions.forEach { permission ->
                                        val isGranted = installed && app.grantedPermissions.contains(permission)
                                        val line = if (current.title == "Runtime permission grants" && installed)
                                            (if (isGranted) "GRANTED • " else "NOT GRANTED • ") + permission else permission
                                        Text("• $line", color = if (current.title == "Runtime permission grants" && isGranted) Green else Grey,
                                            fontSize = 10.sp, modifier = Modifier.padding(top = 5.dp))
                                    }
                                }
                                if (current.title == "Runtime permission grants" && !installed) {
                                    Text("An APK file is not installed, so Android runtime grant status cannot be queried.",
                                        color = Orange, fontSize = 10.sp, modifier = Modifier.padding(top = 8.dp))
                                }
                                Text("Declared permissions are requests, not proof that access was granted or abused.",
                                    color = Orange, fontSize = 9.sp, modifier = Modifier.padding(top = 8.dp))
                            } else if (current.title == "Display name") {
                                OutlinedTextField(value = alias, onValueChange = { alias = it },
                                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                    label = { Text("Custom display name") }, singleLine = true)
                                Button(onClick = { showAliasPreview = true },
                                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                                    Text("Preview custom name")
                                }
                                if (showAliasPreview) {
                                    Text("Preview label: $alias", color = Green,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(top = 8.dp))
                                    Text("Preview only. The installed app's actual Android label is unchanged.",
                                        color = Orange, fontSize = 10.sp)
                                }
                            } else if (current.title == "Icon concept") {
                                Text("Icon design can be planned here. Replacing another app's installed icon is not performed.",
                                    color = Orange, fontSize = 10.sp, modifier = Modifier.padding(top = 12.dp))
                            } else if (current.title == "Open app") {
                                Button(onClick = { openInstalledApp() }, enabled = installed, modifier = Modifier.fillMaxWidth().padding(top = 10.dp)) {
                                    Text(if (installed) "Launch app" else "Imported APK cannot be launched")
                                }
                            } else if (current.title == "Open system app settings") {
                                Button(onClick = { openAppSettings() }, enabled = installed, modifier = Modifier.fillMaxWidth().padding(top = 10.dp)) {
                                    Text(if (installed) "Open Android app settings" else "Not installed on this device")
                                }
                            } else if (current.title == "Export audit summary") {
                                Button(onClick = { exportAudit() }, modifier = Modifier.fillMaxWidth().padding(top = 10.dp)) {
                                    Text("Share audit report")
                                }
                                OutlinedButton(onClick = { pendingPdfText = buildAuditReport(); pdfLauncher.launch("omni-audit-${app.pkg.substringAfterLast('.')}.pdf") }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                                    Text("Save PDF report")
                                }
                            }
                        }
                    }
                }
                item {
                    Text("RELATED CHECKS", color = Green, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                    Text("Return to the category to explore related tools and checks.",
                        color = Grey, fontSize = 10.sp)
                }
            } else if (category != null && subcategory != null) {
                item {
                    Text(subcategory!!, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    Text(category!!.title + " • selected tools", color = Grey, fontSize = 11.sp)
                }
                items(category!!.features.filter { subcategoryFor(category!!.title, it.title) == subcategory }) { item ->
                    WorkspaceFeatureCard(item) {
                        feature = item
                        featureResults = runFeatureAudit(app, item)
                    }
                }
            } else if (category != null) {
                item {
                    Text(category!!.title, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    Text(category!!.subtitle, color = Grey, fontSize = 11.sp)
                    Text("Choose a subcategory to open its tools.", color = Grey, fontSize = 10.sp)
                }
                items(category!!.features.map { subcategoryFor(category!!.title, it.title) }.distinct()) { group ->
                    val count = category!!.features.count { subcategoryFor(category!!.title, it.title) == group }
                    Card(modifier = Modifier.fillMaxWidth().clickable { subcategory = group },
                        colors = CardDefaults.cardColors(containerColor = CardBg), shape = RoundedCornerShape(15.dp)) {
                        Row(Modifier.fillMaxWidth().padding(15.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(group, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                                Text("$count tools inside", color = Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp))
                            }
                            Text("›", color = Green, fontSize = 25.sp)
                        }
                    }
                }
            } else {
                item {
                    Text("Choose a workspace", fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    Text("Open a category, then choose a feature card to see its details and availability.",
                        color = Grey, fontSize = 11.sp)
                }
                items(categories) { group ->
                    Card(
                        modifier = Modifier.fillMaxWidth().clickable { category = group },
                        colors = CardDefaults.cardColors(containerColor = CardBg),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(group.title, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                                Text(group.subtitle, color = Grey, fontSize = 10.sp,
                                    modifier = Modifier.padding(top = 4.dp))
                                Text("${group.features.size} FEATURES", color = Green,
                                    fontSize = 9.sp, fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(top = 7.dp))
                            }
                            Text("›", color = Green, fontSize = 27.sp)
                        }
                    }
                }
                item {
                    Text("AUDIT SNAPSHOT", color = Green, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                    AuditCard("APP IDENTITY", listOf("Version" to app.version,
                        "Type" to if (app.system) "System app" else "User-installed",
                        "Target SDK" to app.targetSdk.toString(), "Installer" to app.installer))
                    AuditCard("SIGNING & INTEGRITY", listOf("Signer SHA-256" to app.signer,
                        "Debuggable flag" to if (app.debug) "ENABLED • REVIEW" else "Not enabled"))
                }
            }
        }
    }
}

@Composable
private fun EndpointAuditPanel() {
    var endpoint by remember { mutableStateOf("https://") }
    var running by remember { mutableStateOf(false) }
    var results by remember { mutableStateOf(emptyList<String>()) }
    val scope = rememberCoroutineScope()
    Column(Modifier.fillMaxWidth().padding(top = 12.dp)) {
        Text("AUTHORIZED HTTPS ENDPOINT", color = Green, fontWeight = FontWeight.Bold, fontSize = 11.sp)
        Text("Enter one endpoint belonging to you or your client. One HEAD request only; redirects are not followed.", color = Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 5.dp))
        OutlinedTextField(value = endpoint, onValueChange = { endpoint = it }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp), singleLine = true, label = { Text("https://api.example.com/health") })
        Button(onClick = {
            scope.launch {
                running = true
                results = inspectHttpsEndpoint(endpoint)
                running = false
            }
        }, enabled = !running && endpoint.trim().startsWith("https://", true), modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
            Text(if (running) "Checking endpoint…" else "Run HTTPS / TLS check")
        }
        if (running) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp), color = Green)
        results.forEach { line ->
            Text("• $line", color = if (line.startsWith("REVIEW")) Orange else Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 6.dp))
        }
        Text("Limitations: this does not crawl routes, test authentication, submit forms, exploit the server, or prove the API is secure.", color = Orange, fontSize = 9.sp, modifier = Modifier.padding(top = 9.dp))
    }
}

@Composable
private fun WorkspaceFeatureCard(feature: WorkspaceFeature, onClick: () -> Unit) {
    val tint = if (feature.available) Green else Orange
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = CardBg),
        shape = RoundedCornerShape(16.dp)
    ) {
        Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Surface(Modifier.size(34.dp), color = tint.copy(alpha = .12f), shape = RoundedCornerShape(11.dp)) {
                Box(contentAlignment = Alignment.Center) {
                    Text(if (feature.available) "✓" else "•", color = tint, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                }
            }
            Spacer(Modifier.width(11.dp))
            Column(Modifier.weight(1f)) {
                Text(feature.title, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                Text(feature.description, color = Grey, fontSize = 10.sp,
                    maxLines = 2, overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(top = 4.dp))
                Surface(color = tint.copy(alpha = .12f), shape = RoundedCornerShape(30.dp),
                    modifier = Modifier.padding(top = 7.dp)) {
                    Text(feature.state, color = tint, fontSize = 8.sp, fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp))
                }
            }
            Text("›", color = Green, fontSize = 24.sp)
        }
    }
}

@Composable
private fun AuditCard(title: String, rows: List<Pair<String, String>>) {
    Card(Modifier.fillMaxWidth().padding(top = 9.dp),
        colors = CardDefaults.cardColors(containerColor = CardBg),
        shape = RoundedCornerShape(15.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text(title, color = Green, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            rows.forEach { (k, v) ->
                Spacer(Modifier.height(7.dp)); Text(k, color = Grey, fontSize = 9.sp)
                Text(v, fontSize = 11.sp)
            }
        }
    }
}

@Composable
private fun Check(label: String, state: String, tint: Color) {
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(7.dp).background(tint, CircleShape))
        Spacer(Modifier.width(8.dp))
        Text(label, fontSize = 10.sp, modifier = Modifier.weight(1f))
        Text(state, color = tint, fontSize = 8.sp, fontWeight = FontWeight.Bold)
    }
}
