package com.omni.cyberlab

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.PackageInfo
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.net.Uri
import android.content.Intent
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import java.io.File
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
    val installer: String, val findings: List<String>, val grantedPermissions: List<String> = emptyList(), val exportedComponents: List<String> = emptyList()
) {
    val status: String get() = when {
        debug -> "HIGH RISK"
        findings.isNotEmpty() -> "REVIEW"
        else -> "INVENTORY ONLY"
    }
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
                    if (Build.VERSION.SDK_INT >= 23 && ai.usesCleartextTraffic) add("Cleartext network traffic is allowed by manifest")
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
                    ai.targetSdkVersion, installer, findings, grantedPermissions, componentDetails)
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
                                        if (Build.VERSION.SDK_INT >= 23 && ai.usesCleartextTraffic) add("Cleartext network traffic is allowed by manifest")
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
                                        signer, false, ai.targetSdkVersion, "Imported APK • not installed", findings, emptyList(), componentDetails)
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
                                    Text("Review flags need manual review; they are not proof an app is hacked. This build inventories metadata only. Behavioral malware detection, network/API testing, billing integrity and exploit confirmation are not implemented.",
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
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically) {
        if (app.icon != null) Image(app.icon.asImageBitmap(), null, Modifier.size(44.dp))
        else Surface(Modifier.size(44.dp), shape = RoundedCornerShape(12.dp), color = Raised) {
            Box(contentAlignment = Alignment.Center) { Text(app.name.take(1), color = Green) }
        }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(app.name, fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(app.pkg, color = Grey, fontSize = 9.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text((if (app.system) "SYSTEM APP" else "USER APP") + "  •  v" + app.version,
                color = Grey.copy(alpha = 0.82f), fontSize = 8.sp, maxLines = 1,
                overflow = TextOverflow.Ellipsis)
            Spacer(Modifier.height(4.dp))
            Status(app.status)
        }
        Text("›", color = Grey, fontSize = 24.sp)
    }
    HorizontalDivider(color = Raised)
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

@Composable
private fun Detail(app: AppRow, onBack: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val installed = app.installer != "Imported APK • not installed"
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
    fun exportAudit() {
        val report = buildString {
            appendLine("OMNI CYBER LAB — APP AUDIT")
            appendLine("App: " + app.name)
            appendLine("Package: " + app.pkg)
            appendLine("Version: " + app.version)
            appendLine("Target SDK: " + app.targetSdk)
            appendLine("Installer: " + app.installer)
            appendLine("Debuggable: " + app.debug)
            appendLine("Exported components: " + app.exported)
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
            appendLine("Review signals:")
            if (app.findings.isEmpty()) appendLine("- No basic metadata flags raised")
            else app.findings.forEach { appendLine("- " + it) }
            appendLine("Static metadata only; not a malware verdict or full penetration test.")
        }
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
                WorkspaceFeature("Signer & integrity", "Inspect the signing certificate fingerprint.", if (app.signer == "Unavailable") "UNAVAILABLE" else "CHECKED", true),
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
                WorkspaceFeature("API endpoints", "Endpoint discovery and API security checks are not implemented.", "NOT TESTED"),
                WorkspaceFeature("TLS & certificates", "Live TLS connection validation is not implemented.", "NOT TESTED"),
                WorkspaceFeature("Offline behavior", "Runtime offline behavior has not been tested.", "NOT TESTED")
            )),
            WorkspaceCategory("Storage & data", "App storage and data handling", listOf(
                WorkspaceFeature("Storage footprint", "App storage usage is not currently collected.", "NOT IMPLEMENTED"),
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
                WorkspaceFeature("Uninstall / disable", "Use Android system controls; protected system apps may not allow changes.", "SYSTEM CONTROL")
            ))
        )
    }
    var category by remember { mutableStateOf<WorkspaceCategory?>(null) }
    var feature by remember { mutableStateOf<WorkspaceFeature?>(null) }
    var alias by remember(app.pkg) { mutableStateOf(app.name) }
    var showAliasPreview by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = {
                when {
                    feature != null -> feature = null
                    category != null -> category = null
                    else -> onBack()
                }
            }) { Icon(Icons.Default.ArrowBack, "Back") }
            Column(Modifier.weight(1f)) {
                Text("APP WORKSPACE", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                Text(
                    when {
                        feature != null -> feature!!.title
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
                            if (current.title == "Debug & exported components") {
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
                            }
                        }
                    }
                }
                item {
                    Text("RELATED CHECKS", color = Green, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                    Text("Return to the category to explore related tools and checks.",
                        color = Grey, fontSize = 10.sp)
                }
            } else if (category != null) {
                item {
                    Text(category!!.title, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    Text(category!!.subtitle, color = Grey, fontSize = 11.sp)
                }
                items(category!!.features) { item ->
                    WorkspaceFeatureCard(item) { feature = item }
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
private fun WorkspaceFeatureCard(feature: WorkspaceFeature, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = CardBg),
        shape = RoundedCornerShape(14.dp)
    ) {
        Row(Modifier.fillMaxWidth().padding(13.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(feature.title, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                Text(feature.description, color = Grey, fontSize = 10.sp,
                    maxLines = 2, overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(top = 4.dp))
                Text(feature.state, color = if (feature.available) Green else Orange,
                    fontSize = 9.sp, fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 7.dp))
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
