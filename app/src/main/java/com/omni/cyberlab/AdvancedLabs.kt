package com.omni.cyberlab

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import java.security.MessageDigest

private val LabGreen = Color(0xFF55E6A5)
private val LabMuted = Color(0xFF9AA6B2)
private val LabPanel = Color(0xFF18232D)
private val LabWarn = Color(0xFFFFB454)

private fun labSha256(file: File): String = MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02X".format(it) }

private fun listEditableApkEntries(apk: File): List<String> {
    require(apk.isFile && apk.length() <= 100L * 1024L * 1024L) { "APK missing or larger than 100 MB." }
    return ZipFile(apk).use { zip ->
        val out = mutableListOf<String>()
        val entries = zip.entries()
        var count = 0
        while (entries.hasMoreElements() && count++ < 6000) {
            val e = entries.nextElement()
            val n = e.name
            val allowed = (n.startsWith("assets/") || n.startsWith("res/raw/")) && !e.isDirectory && e.size >= 0L && e.size <= 262144L
            val textLike = allowed && !n.endsWith(".png", true) && !n.endsWith(".jpg", true) && !n.endsWith(".webp", true) && !n.endsWith(".so", true) && !n.endsWith(".dex", true)
            if (textLike) out.add(n)
        }
        out
    }
}

private fun readEditableEntry(apk: File, entryName: String): String {
    require(entryName.startsWith("assets/") || entryName.startsWith("res/raw/")) { "Only assets/ and res/raw/ entries are editable in this lab." }
    return ZipFile(apk).use { zip ->
        val e = zip.getEntry(entryName) ?: error("Entry not found in APK.")
        require(!e.isDirectory && e.size in 0..262144) { "Entry exceeds the 256 KB text-edit limit." }
        val bytes = zip.getInputStream(e).use { it.readBytes() }
        require(bytes.none { it == 0.toByte() }) { "Binary content is not editable as text." }
        bytes.toString(Charsets.UTF_8)
    }
}

private fun buildPatchedApk(source: File, entryName: String, replacement: String, output: File): File {
    require(source.isFile && source.length() <= 100L * 1024L * 1024L) { "Source APK missing or over 100 MB." }
    require(entryName.startsWith("assets/") || entryName.startsWith("res/raw/")) { "Only assets/ and res/raw/ text entries may be modified." }
    require(replacement.toByteArray(Charsets.UTF_8).size <= 262144) { "Edited text exceeds 256 KB." }
    var replaced = false
    ZipFile(source).use { zip ->
        ZipOutputStream(output.outputStream().buffered()).use { out ->
            val entries = zip.entries(); var count = 0; var total = 0L
            while (entries.hasMoreElements()) {
                val e = entries.nextElement(); require(++count <= 8000) { "APK has too many entries." }
                if (e.isDirectory) continue
                if (e.name.startsWith("META-INF/") && (e.name.endsWith(".RSA", true) || e.name.endsWith(".DSA", true) || e.name.endsWith(".EC", true) || e.name.endsWith(".SF", true) || e.name.endsWith("MANIFEST.MF", true))) continue
                val bytes = if (e.name == entryName) { replaced = true; replacement.toByteArray(Charsets.UTF_8) } else {
                    require(e.size >= 0L && e.size <= 30L * 1024L * 1024L) { "An APK entry exceeds the 30 MB safety limit." }
                    zip.getInputStream(e).use { it.readBytes() }
                }
                total += bytes.size; require(total <= 150L * 1024L * 1024L) { "Expanded APK exceeds the 150 MB safety limit." }
                val next = ZipEntry(e.name).apply { time = e.time; comment = e.comment }
                out.putNextEntry(next); out.write(bytes); out.closeEntry()
            }
        }
    }
    require(replaced) { "Selected entry was not found." }
    return output
}

@Composable
fun AdvancedModificationBillingLabs(context: Context, packageName: String, apkPath: String?, initialTab: Int = 0, modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    val prefs = remember(context, packageName) { context.getSharedPreferences("omni_advanced_labs", Context.MODE_PRIVATE) }
    var tab by remember(packageName, initialTab) { mutableStateOf(initialTab.coerceIn(0, 1)) }
    var entries by remember { mutableStateOf(emptyList<String>()) }
    var selectedEntry by remember { mutableStateOf("") }
    var editedText by remember { mutableStateOf("") }
    var patchStatus by remember { mutableStateOf("Select an imported APK with assets/ or res/raw/ text files.") }
    var patchedFile by remember { mutableStateOf<File?>(null) }
    var busy by remember { mutableStateOf(false) }
    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { uri: Uri? ->
        if (uri != null && patchedFile?.isFile == true) {
            scope.launch {
                try { withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(uri)?.use { out -> patchedFile!!.inputStream().use { it.copyTo(out) } } ?: error("Could not open destination.") }; patchStatus = "Exported modified unsigned APK. Sign it with your own keystore before installation." }
                catch (e: Exception) { patchStatus = "Export failed: ${e.message ?: "unknown error"}" }
            }
        }
    }
    val productKey = "billing_product_$packageName"
    val productIdSaved = prefs.getString(productKey, "test.premium.monthly") ?: "test.premium.monthly"
    var productId by remember(packageName) { mutableStateOf(productIdSaved) }
    var purchaseState by remember(packageName) { mutableStateOf(prefs.getString("billing_state_$packageName", "NOT PURCHASED") ?: "NOT PURCHASED") }
    var eventLog by remember(packageName) { mutableStateOf(prefs.getString("billing_log_$packageName", "") ?: "") }
    fun recordBilling(next: String, detail: String) {
        purchaseState = next
        val line = "${java.text.DateFormat.getDateTimeInstance().format(java.util.Date())} • $next • $detail"
        eventLog = (eventLog + if (eventLog.isBlank()) "" else "\n" + line).takeLast(12000)
        prefs.edit().putString("billing_state_$packageName", next).putString("billing_log_$packageName", eventLog).putString(productKey, productId).apply()
    }
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("ADVANCED OWNER-ONLY LABS", color = LabGreen, fontWeight = FontWeight.ExtraBold, fontSize = 12.sp)
        Text("Use only an APK and billing backend you own or are explicitly authorized to test. These tools do not unlock third-party apps or alter real store entitlements.", color = LabWarn, fontSize = 10.sp)
        TabRow(selectedTabIndex = tab, containerColor = LabPanel) {
            Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("APK PATCH LAB", fontSize = 10.sp) })
            Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("IAP / LICENSE SIM", fontSize = 10.sp) })
        }
        if (tab == 0) {
            Text("TEXT RESOURCE / ASSET PATCHER", color = LabGreen, fontWeight = FontWeight.Bold, fontSize = 11.sp)
            Text("Source: ${apkPath?.let { File(it).name } ?: "No APK imported"}", color = LabMuted, fontSize = 10.sp)
            Button(onClick = { scope.launch { busy = true; try { entries = withContext(Dispatchers.IO) { require(!apkPath.isNullOrBlank()) { "Import an APK first." }; listEditableApkEntries(File(apkPath)) }; selectedEntry = entries.firstOrNull().orEmpty(); editedText = if (selectedEntry.isNotBlank()) withContext(Dispatchers.IO) { readEditableEntry(File(apkPath!!), selectedEntry) } else ""; patchStatus = "${entries.size} editable text entries found. Binary resources and manifest are intentionally excluded." } catch (e: Exception) { patchStatus = "Scan failed: ${e.message}" }; busy = false } }, enabled = !busy && !apkPath.isNullOrBlank(), modifier = Modifier.fillMaxWidth()) { Text(if (busy) "Scanning…" else "Scan editable APK entries") }
            if (entries.isNotEmpty()) {
                var expanded by remember { mutableStateOf(false) }
                OutlinedButton(onClick = { expanded = true }, modifier = Modifier.fillMaxWidth()) { Text(if (selectedEntry.isBlank()) "Choose text entry" else selectedEntry) }
                DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }, modifier = Modifier.heightIn(max = 280.dp)) {
                    entries.forEach { name -> DropdownMenuItem(text = { Text(name, fontSize = 10.sp) }, onClick = { selectedEntry = name; expanded = false; scope.launch { try { editedText = withContext(Dispatchers.IO) { readEditableEntry(File(apkPath!!), name) }; patchStatus = "Loaded $name" } catch (e: Exception) { patchStatus = "Load failed: ${e.message}" } } }) }
                }
                OutlinedTextField(value = editedText, onValueChange = { editedText = it }, modifier = Modifier.fillMaxWidth().heightIn(min = 140.dp, max = 300.dp), label = { Text("Edited text content") }, minLines = 6)
                Button(onClick = { scope.launch { busy = true; try { patchedFile = withContext(Dispatchers.IO) { val src = File(apkPath!!); val out = File(context.cacheDir, "omni-patched-${System.currentTimeMillis()}.apk"); buildPatchedApk(src, selectedEntry, editedText, out) }; patchStatus = "Patch package built • SHA-256 ${withContext(Dispatchers.IO) { labSha256(patchedFile!!) }.take(32)}… • signature blocks removed." } catch (e: Exception) { patchStatus = "Build failed: ${e.message}" }; busy = false } }, enabled = !busy && selectedEntry.isNotBlank() && !apkPath.isNullOrBlank(), modifier = Modifier.fillMaxWidth()) { Text(if (busy) "Building…" else "Build modified unsigned APK") }
                Button(onClick = { exportLauncher.launch("omni-patched-${packageName.substringAfterLast(".")}.apk") }, enabled = patchedFile?.isFile == true, modifier = Modifier.fillMaxWidth()) { Text("Export modified APK") }
            }
            Text("STATUS: $patchStatus", color = LabMuted, fontSize = 10.sp)
            Text("Supported now: bounded text files under assets/ and res/raw/. The builder preserves other ZIP entries, removes stale APK signature files, and outputs an unsigned APK. Binary AndroidManifest.xml, compiled resources.arsc, layouts, icons, native libraries and DEX are not edited by this patcher. Existing Smali DEX workflow remains separate. Sign with your own key and verify the output before install.", color = LabWarn, fontSize = 9.sp)
        } else {
            Text("SIMULATED BILLING + LICENSE STATE MACHINE", color = LabGreen, fontWeight = FontWeight.Bold, fontSize = 11.sp)
            OutlinedTextField(value = productId, onValueChange = { productId = it.take(180) }, modifier = Modifier.fillMaxWidth(), label = { Text("Your test product ID") }, singleLine = true)
            Text("Current simulated entitlement: $purchaseState", color = LabGreen, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            Text("These are local mock events only. No Google Play purchase, payment, receipt, account or backend is contacted.", color = LabWarn, fontSize = 10.sp)
            val actions = listOf("PURCHASED" to "Simulate approved test purchase", "PENDING" to "Simulate pending purchase", "CANCELLED" to "Simulate user cancellation", "EXPIRED" to "Simulate subscription expiry", "REFUNDED" to "Simulate refund / revoke", "GRACE PERIOD" to "Simulate billing grace period", "ON HOLD" to "Simulate account hold", "LICENSE INVALID" to "Simulate invalid license response", "RESTORED" to "Simulate restore purchases")
            actions.forEach { (state, label) ->
                OutlinedButton(onClick = { if (productId.isBlank()) recordBilling("ERROR", "Product ID required") else recordBilling(state, "Mock event for $productId; no real entitlement granted.") }, modifier = Modifier.fillMaxWidth()) { Text(label, fontSize = 10.sp) }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { recordBilling("NOT PURCHASED", "Reset local test state") }, modifier = Modifier.weight(1f)) { Text("Reset state") }
                OutlinedButton(onClick = { eventLog = ""; prefs.edit().remove("billing_log_$packageName").apply() }, modifier = Modifier.weight(1f)) { Text("Clear log") }
            }
            Text("EVENT AUDIT LOG", color = LabGreen, fontWeight = FontWeight.Bold, fontSize = 10.sp)
            if (eventLog.isBlank()) Text("No simulated events yet.", color = LabMuted, fontSize = 10.sp) else LazyColumn(Modifier.heightIn(max = 220.dp)) { items(eventLog.lines()) { Text(it, color = LabMuted, fontSize = 9.sp, modifier = Modifier.padding(vertical = 3.dp)) } }
            Text("Production integration still requires your own Play Console license testers, test-track product IDs, official Play Billing client, server-side purchase-token verification, idempotent entitlement service, acknowledgement/consumption, RTDN handling and audit logging. This local simulator is a QA harness, not a replacement for those systems.", color = LabWarn, fontSize = 9.sp)
        }
    }
}