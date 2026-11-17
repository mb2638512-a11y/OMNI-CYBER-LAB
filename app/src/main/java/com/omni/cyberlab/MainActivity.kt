package com.omni.cyberlab

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
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
    val installer: String, val findings: List<String>
) {
    val status: String get() = when {
        debug -> "HIGH RISK"
        findings.isNotEmpty() -> "REVIEW"
        else -> "INVENTORY CHECKED"
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
                val debug = ai.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
                val exported = (p.activities?.count { it.exported } ?: 0) +
                    (p.services?.count { it.exported } ?: 0) +
                    (p.receivers?.count { it.exported } ?: 0) +
                    (p.providers?.count { it.exported } ?: 0)
                val cert = if (Build.VERSION.SDK_INT >= 28)
                    p.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray() else null
                val signer = cert?.let { bytes ->
                    MessageDigest.getInstance("SHA-256").digest(bytes)
                        .joinToString(":") { "%02X".format(it) }
                } ?: "Unavailable"
                val findings = buildList {
                    if (debug) add("Debuggable build flag is enabled")
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
                    ai.targetSdkVersion, installer, findings)
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
                var scanning by remember { mutableStateOf(false) }
                var scanTime by remember { mutableStateOf("Waiting for first inventory") }
                var bridge by remember { mutableStateOf("Checking Shizuku…") }
                var settings by remember { mutableStateOf(false) }
                val scope = rememberCoroutineScope()
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
                                Text("Installed applications", fontSize = 22.sp, fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(top = 8.dp))
                                Text("${shown.size} apps • Tap an app to inspect its metadata",
                                    color = Grey, fontSize = 11.sp, modifier = Modifier.padding(top = 3.dp, bottom = 10.dp))
                                OutlinedTextField(value = query, onValueChange = { query = it },
                                    modifier = Modifier.fillMaxWidth(), singleLine = true,
                                    placeholder = { Text("Search app or package…") },
                                    leadingIcon = { Icon(Icons.Default.Search, null) },
                                    shape = RoundedCornerShape(14.dp))
                                Spacer(Modifier.height(8.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                                    listOf("ALL", "REVIEW", "USER", "SYSTEM").forEach {
                                        FilterChip(selected = filter == it, onClick = { filter = it },
                                            label = { Text(it, fontSize = 9.sp) })
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
            Spacer(Modifier.height(4.dp))
            Status(app.status)
        }
        Text("›", color = Grey, fontSize = 24.sp)
    }
    HorizontalDivider(color = Raised)
}

@Composable
private fun Detail(app: AppRow, onBack: () -> Unit) {
    Column(Modifier.fillMaxSize()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, "Back") }
            Text("APPLICATION SECURITY AUDIT", fontSize = 11.sp, fontWeight = FontWeight.Bold)
        }
        LazyColumn(contentPadding = PaddingValues(bottom = 25.dp)) {
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (app.icon != null) Image(app.icon.asImageBitmap(), null, Modifier.size(58.dp))
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(app.name, fontSize = 21.sp, fontWeight = FontWeight.Bold)
                        Text(app.pkg, color = Grey, fontSize = 10.sp)
                        Spacer(Modifier.height(5.dp)); Status(app.status)
                    }
                }
                AuditCard("APP IDENTITY", listOf("Version" to app.version,
                    "Type" to if (app.system) "System app" else "User-installed",
                    "Target SDK" to app.targetSdk.toString(), "Installer" to app.installer))
                AuditCard("SIGNING & INTEGRITY", listOf("Signer SHA-256" to app.signer,
                    "Debuggable flag" to if (app.debug) "ENABLED • HIGH RISK" else "Not enabled"))
                AuditCard("PERMISSIONS & COMPONENTS", listOf(
                    "Requested permissions" to app.permissions.size.toString(),
                    "Exported components" to app.exported.toString(),
                    "Sensitive permissions" to if (app.findings.any { it.contains("Sensitive") })
                        "Present • review necessity" else "No match in basic filter"))
                Card(Modifier.fillMaxWidth().padding(top = 10.dp),
                    colors = CardDefaults.cardColors(containerColor = CardBg),
                    shape = RoundedCornerShape(15.dp)) {
                    Column(Modifier.padding(13.dp)) {
                        Text("CHECK-BY-CHECK INDICATORS", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        Spacer(Modifier.height(8.dp))
                        Check("Package identity & version", "CHECKED", Green)
                        Check("Signing certificate fingerprint",
                            if (app.signer == "Unavailable") "UNAVAILABLE" else "CHECKED",
                            if (app.signer == "Unavailable") Orange else Green)
                        Check("Requested permissions inventory", "CHECKED", Green)
                        Check("Exported components inventory", "CHECKED", Green)
                        Check("Debuggable build flag", if (app.debug) "FLAG FOUND" else "CHECKED",
                            if (app.debug) Red else Green)
                        Check("Live behavior / malware activity", "NOT TESTED", Grey)
                        Check("Private app data / sandbox", "NOT ACCESSIBLE", Grey)
                        Check("Network traffic / API security", "NOT TESTED", Grey)
                        Check("In-app purchases / subscriptions", "NOT TESTED", Grey)
                        Check("Exploit / compromise confirmation", "NOT TESTED", Grey)
                    }
                }
                if (app.findings.isNotEmpty()) {
                    Text("ITEMS TO REVIEW", fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(top = 14.dp, bottom = 6.dp))
                    app.findings.forEach { Text("• $it", color = Orange, fontSize = 11.sp,
                        modifier = Modifier.padding(vertical = 3.dp)) }
                } else Text("No issue detected by these basic metadata checks. This does not prove the app is vulnerability-free.",
                    color = Green, fontSize = 11.sp, modifier = Modifier.padding(top = 13.dp))
                Text("A risk flag is not proof of hacking. This version inventories metadata only; behavioral, network, billing and exploit testing are not implemented.",
                    color = Grey, fontSize = 10.sp, modifier = Modifier.padding(top = 12.dp))
                Text("REQUESTED PERMISSIONS", fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 14.dp, bottom = 7.dp))
                app.permissions.forEach { Text(it, color = Grey, fontSize = 9.sp,
                    modifier = Modifier.padding(vertical = 2.dp)) }
            }
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
