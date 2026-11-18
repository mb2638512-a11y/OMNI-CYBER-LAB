package com.omni.cyberlab

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

private data class CoreApkSnapshot(
    val sha256: String, val entries: Int, val dex: Int, val nativeLibs: Int,
    val resources: Int, val assets: Int, val textCandidates: Int, val billingMarkers: Int,
    val adMarkers: Int, val signatureFiles: Int, val warnings: List<String>
)

private fun inspectCoreApk(file: File): CoreApkSnapshot {
    require(file.isFile && file.length() in 1..(150L * 1024L * 1024L)) { "Select a readable APK up to 150 MB." }
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().buffered().use { input ->
        val buffer = ByteArray(8192)
        while (true) { val n = input.read(buffer); if (n <= 0) break; digest.update(buffer, 0, n) }
    }
    val warnings = mutableListOf<String>()
    var count = 0; var dex = 0; var libs = 0; var resources = 0; var assets = 0
    var text = 0; var billing = 0; var ads = 0; var signatures = 0
    val billingTerms = listOf("BillingClient", "purchaseToken", "acknowledgePurchase", "queryPurchases", "isPremium", "licenseValid")
    val adTerms = listOf("com.google.android.gms.ads", "com.applovin", "com.unity3d.ads", "com.facebook.ads", "ironsource")
    ZipFile(file).use { zip ->
        val entries = zip.entries()
        while (entries.hasMoreElements()) {
            val entry = entries.nextElement(); count++
            require(count <= 8000) { "APK exceeds the 8,000-entry inspection limit." }
            val name = entry.name
            if (name.matches(Regex("classes([0-9]*)\\.dex"))) dex++
            if (name.startsWith("lib/") && name.endsWith(".so")) libs++
            if (name.startsWith("res/")) resources++
            if (name.startsWith("assets/")) assets++
            if (name.startsWith("META-INF/") && (name.endsWith(".RSA", true) || name.endsWith(".DSA", true) || name.endsWith(".EC", true) || name.endsWith(".SF", true))) signatures++
            val candidate = !entry.isDirectory && (name.startsWith("assets/") || name.startsWith("res/raw/")) && entry.size in 1..262144 && !name.endsWith(".png", true) && !name.endsWith(".jpg", true) && !name.endsWith(".webp", true) && !name.endsWith(".dex", true) && !name.endsWith(".so", true)
            if (candidate) {
                text++
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                if (bytes.none { b -> b == 0.toByte() }) {
                    val sample = bytes.toString(Charsets.UTF_8)
                    billing += billingTerms.count { sample.contains(it, true) }
                    ads += adTerms.count { sample.contains(it, true) }
                }
            }
        }
    }
    if (dex == 0) warnings += "No classes*.dex entry detected; confirm this is a standard APK."
    if (signatures == 0) warnings += "No conventional META-INF signature files detected; APK v2/v3 signatures are not represented by these ZIP entries."
    return CoreApkSnapshot(digest.digest().joinToString("") { "%02X".format(it) }, count, dex, libs, resources, assets, text, billing, ads, signatures, warnings)
}

@Composable
fun LuckyStyleCorePanel(context: Context, apkPath: String?, modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    var running by remember { mutableStateOf(false) }
    var snapshot by remember { mutableStateOf<CoreApkSnapshot?>(null) }
    var status by remember { mutableStateOf("Import an APK, then run the core preflight scan.") }
    val green = Color(0xFF55E6A5); val muted = Color(0xFF9AA6B2); val panel = Color(0xFF18232D); val amber = Color(0xFFFFB454)
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Card(colors = CardDefaults.cardColors(containerColor = panel)) {
            Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                Text("OMNI PATCH ENGINE • CORE WORKSPACE", color = green, fontSize = 12.sp, fontWeight = FontWeight.ExtraBold)
                Text("Lucky Patcher-inspired workflow: inspect → backup → authorized patch → rebuild → sign → validate. This preflight performs bounded APK archive inspection; it does not modify the source APK.", color = muted, fontSize = 10.sp)
                Text("TARGET: ${apkPath?.let { File(it).name } ?: "No APK selected"}", color = muted, fontSize = 10.sp)
                OutlinedButton(onClick = {
                    scope.launch {
                        running = true
                        try { snapshot = withContext(Dispatchers.IO) { require(!apkPath.isNullOrBlank()) { "Import an APK first." }; inspectCoreApk(File(apkPath)) }; status = "Preflight complete. Review the inventory and continue in the authorized APK patch lab." }
                        catch (e: Exception) { snapshot = null; status = "Preflight failed: ${e.message ?: "unknown error"}" }
                        running = false
                    }
                }, enabled = !running && !apkPath.isNullOrBlank(), modifier = Modifier.fillMaxWidth()) { Text(if (running) "Inspecting APK…" else "Run core APK preflight") }
                Text("STATUS: $status", color = amber, fontSize = 10.sp)
                snapshot?.let { s ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) { Text("ZIP entries: ${s.entries}", color = muted, fontSize = 10.sp); Text("DEX: ${s.dex}", color = muted, fontSize = 10.sp); Text("Native libs: ${s.nativeLibs}", color = muted, fontSize = 10.sp) }
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) { Text("Resources: ${s.resources}", color = muted, fontSize = 10.sp); Text("Assets: ${s.assets}", color = muted, fontSize = 10.sp); Text("Text candidates: ${s.textCandidates}", color = muted, fontSize = 10.sp) }
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) { Text("Billing markers: ${s.billingMarkers}", color = muted, fontSize = 10.sp); Text("Ad markers: ${s.adMarkers}", color = muted, fontSize = 10.sp); Text("Signature files: ${s.signatureFiles}", color = muted, fontSize = 10.sp) }
                    Text("SOURCE SHA-256", color = green, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                    Text(s.sha256, color = muted, fontSize = 9.sp)
                    s.warnings.forEach { Text("• $it", color = amber, fontSize = 9.sp) }
                }
                Text("Next modules: full resource decode/rebuild (Windows Apktool companion), on-device text asset patching, Smali DEX workflow, signing, APK diff and install validation. Billing/ad marker counts are simple string matches, not proof of behavior or vulnerability.", color = amber, fontSize = 9.sp)
            }
        }
    }
}