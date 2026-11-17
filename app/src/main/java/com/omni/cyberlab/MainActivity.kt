package com.omni.cyberlab

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku
import java.security.MessageDigest

data class AppRow(
    val label: String,
    val pkg: String,
    val version: String,
    val permissions: List<String>,
    val exported: Int,
    val debuggable: Boolean,
    val signer: String
)

class MainActivity : ComponentActivity() {
    private fun installedApps(): List<AppRow> {
        val pm = packageManager
        return pm.getInstalledPackages(
            PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or
                PackageManager.GET_PROVIDERS or
                (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else 0)
        ).mapNotNull { p ->
            try {
                val ai = p.applicationInfo ?: return@mapNotNull null
                val exported = (p.activities?.count { it.exported } ?: 0) +
                    (p.services?.count { it.exported } ?: 0) +
                    (p.receivers?.count { it.exported } ?: 0) +
                    (p.providers?.count { it.exported } ?: 0)
                val cert = if (Build.VERSION.SDK_INT >= 28) {
                    p.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
                } else null
                val fingerprint = cert?.let {
                    MessageDigest.getInstance("SHA-256").digest(it)
                        .joinToString(":") { b -> "%02X".format(b) }
                } ?: "Unavailable on this Android version"
                AppRow(
                    pm.getApplicationLabel(ai).toString(),
                    p.packageName,
                    p.versionName ?: "Unknown",
                    p.requestedPermissions?.toList() ?: emptyList(),
                    exported,
                    (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
                    fingerprint
                )
            } catch (_: Exception) {
                null
            }
        }.sortedBy { it.label.lowercase() }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                var apps by remember { mutableStateOf(emptyList<AppRow>()) }
                var selected by remember { mutableStateOf<AppRow?>(null) }
                var query by remember { mutableStateOf("") }
                var busy by remember { mutableStateOf(false) }
                var bridge by remember { mutableStateOf("Checking Shizuku…") }
                val scope = rememberCoroutineScope()

                fun refreshBridge() {
                    bridge = try {
                        when {
                            !Shizuku.pingBinder() -> "Shizuku service is not running"
                            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED ->
                                "Connected • permission granted"
                            else -> "Service connected • permission required"
                        }
                    } catch (e: Exception) {
                        "Unavailable: ${e.message}"
                    }
                }

                fun scan() {
                    scope.launch {
                        busy = true
                        apps = withContext(Dispatchers.IO) { installedApps() }
                        busy = false
                    }
                }

                LaunchedEffect(Unit) {
                    scan()
                    refreshBridge()
                }

                Column(Modifier.fillMaxSize().padding(16.dp)) {
                    Text("OMNI CYBER LAB", style = MaterialTheme.typography.headlineSmall)
                    Text("Offline-first Android security inventory")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { scan() }, enabled = !busy) {
                            Text(if (busy) "Scanning…" else "Auto Scan")
                        }
                        OutlinedButton(onClick = { selected = null }) { Text("All apps") }
                    }
                    Card(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                        Column(Modifier.padding(12.dp)) {
                            Text("Shizuku / ADB bridge", style = MaterialTheme.typography.titleMedium)
                            Text(bridge)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = {
                                    try {
                                        if (!Shizuku.pingBinder()) {
                                            bridge = "Start Shizuku service first"
                                        } else if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                                            Shizuku.requestPermission(4102)
                                            bridge = "Permission request sent; approve it in Shizuku"
                                        } else {
                                            refreshBridge()
                                        }
                                    } catch (e: Exception) {
                                        bridge = "Error: ${e.message}"
                                    }
                                }) { Text("Grant / Check") }
                                OutlinedButton(onClick = { refreshBridge() }) { Text("Refresh") }
                            }
                            Text(
                                "Shizuku connection status is checked here. This build does not execute shell commands; diagnostics remain read-only app metadata until the authorized service layer is implemented.",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                    OutlinedTextField(
                        value = query,
                        onValueChange = { query = it },
                        label = { Text("Search installed apps") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text("${apps.size} installed packages visible to Android")
                    selected?.let { app ->
                        Card(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                            Column(Modifier.padding(12.dp)) {
                                Text(app.label, style = MaterialTheme.typography.titleLarge)
                                Text(app.pkg)
                                Text("Version: ${app.version}")
                                Text("Exported components: ${app.exported}")
                                Text("Debuggable: ${app.debuggable}")
                                Text("Signer SHA-256: ${app.signer}")
                                Text("Requested permissions (${app.permissions.size})")
                                app.permissions.forEach {
                                    Text("• $it", style = MaterialTheme.typography.bodySmall)
                                }
                                if (app.debuggable) Text("HIGH: debuggable build flag detected")
                                if (app.exported > 0) Text("REVIEW: inspect exported component access controls")
                                if (app.permissions.any {
                                        it.contains("SMS") || it.contains("CONTACTS") ||
                                            it.contains("RECORD_AUDIO") || it.contains("LOCATION")
                                    }) {
                                    Text("REVIEW: sensitive permission requested")
                                }
                            }
                        }
                    }
                    LazyColumn(Modifier.weight(1f)) {
                        items(apps.filter {
                            it.label.contains(query, true) || it.pkg.contains(query, true)
                        }) { app ->
                            ListItem(
                                headlineContent = { Text(app.label) },
                                supportingContent = { Text("${app.pkg} • ${app.version}") },
                                trailingContent = {
                                    TextButton(onClick = { selected = app }) { Text("Inspect") }
                                }
                            )
                            HorizontalDivider()
                        }
                    }
                    Text(
                        "Metadata audit only. Android sandbox protects private app data; no payment bypass or credential access is performed.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
    }
}
