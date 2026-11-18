package com.omni.cyberlab

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
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
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

private val BillingAuditGreen = Color(0xFF55E6A5)
private val BillingAuditAmber = Color(0xFFFFB454)
private val BillingAuditMuted = Color(0xFF9AA6B2)

private data class BillingAuditFinding(val category: String, val severity: String, val title: String, val evidence: String, val recommendation: String)

private fun runBillingStaticAudit(apk: File): List<BillingAuditFinding> {
    require(apk.isFile && apk.length() <= 150L * 1024L * 1024L) { "APK missing or larger than 150 MB." }
    val dexText = StringBuilder()
    var dexCount = 0
    ZipFile(apk).use { zip ->
        val entries = zip.entries()
        while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            if (entry.name.matches(Regex("classes(\\d+)?\\.dex")) && entry.size in 1..(12L * 1024L * 1024L)) {
                dexCount++
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                val printable = bytes.filter { (it.toInt() and 0xff) in 32..126 || it == 10.toByte() || it == 13.toByte() }.toByteArray()
                dexText.append(printable.toString(Charsets.UTF_8)).append("\\n")
            }
        }
    }
    val text = dexText.toString()
    val lower = text.lowercase()
    val findings = mutableListOf<BillingAuditFinding>()
    fun addIf(condition: Boolean, category: String, severity: String, title: String, evidence: String, recommendation: String) {
        if (condition) findings.add(BillingAuditFinding(category, severity, title, evidence, recommendation))
    }
    val hasBillingClient = lower.contains("com.android.billingclient") || lower.contains("billingclient")
    val hasPurchaseToken = lower.contains("purchasetoken") || lower.contains("getpurchasetoken")
    val hasBackendVerify = lower.contains("purchases.products") || lower.contains("subscriptionsv2") || lower.contains("verify-purchase") || lower.contains("verify_purchase") || lower.contains("purchase/verify")
    val hasAcknowledge = lower.contains("acknowledgepurchase") || lower.contains("acknowledge")
    val hasPending = lower.contains("pending") && lower.contains("purchase")
    val hasObfuscatedAccount = lower.contains("obfuscatedaccountid") || lower.contains("obfuscatedprofileid")
    addIf(hasBillingClient, "PLAY BILLING", "INFO", "Google Play Billing client indicators found", "DEX contains BillingClient-related strings.", "Confirm every completed purchase is sent to a trusted backend for Google Play Developer API verification.")
    addIf(!hasBillingClient, "PLAY BILLING", "INFO", "No recognizable Play Billing client marker", "No common BillingClient marker was found in sampled DEX strings.", "The app may use another billing SDK, obfuscation or server-managed purchases. Review the actual purchase architecture.")
    addIf(hasPurchaseToken, "PURCHASE VERIFICATION", "INFO", "Purchase-token handling indicator found", "DEX contains purchase-token-related strings.", "Ensure tokens are verified server-side, stored uniquely and never trusted from client UI state alone.")
    addIf(hasBillingClient && !hasBackendVerify, "PURCHASE VERIFICATION", "HIGH", "No recognizable backend verification marker", "Billing client marker exists but common backend verification route/API markers were not found.", "Manually verify that the backend calls Google Play Developer API before granting entitlements. Static absence is not proof of a vulnerability.")
    addIf(hasBillingClient && !hasAcknowledge, "PURCHASE LIFECYCLE", "MEDIUM", "No recognizable acknowledgement marker", "Common purchase acknowledgement strings were not found.", "Review acknowledgement/consumption handling for the product type and avoid acknowledging rejected or unfulfilled purchases.")
    addIf(hasBillingClient && !hasPending, "PURCHASE LIFECYCLE", "MEDIUM", "Pending-purchase handling not evident", "No combined pending/purchase marker was found in sampled DEX strings.", "Test pending purchases and confirm they never grant paid entitlements until the purchase reaches PURCHASED.")
    addIf(hasBillingClient && !hasObfuscatedAccount, "ACCOUNT BINDING", "LOW", "Obfuscated account binding not evident", "No obfuscated account/profile identifier marker was found.", "Consider binding purchases to the signed-in account with obfuscatedAccountId/profileId and validate the mapping on the backend.")
    val entitlementMarkers = listOf("ispremium", "is_premium", "ispro", "is_pro", "premiumenabled", "licensevalid", "haspremium", "subscriptionactive")
    val localHits = entitlementMarkers.filter { lower.contains(it) }
    addIf(localHits.isNotEmpty(), "CLIENT TRUST BOUNDARY", "REVIEW", "Client-side entitlement markers found", "Matched marker names: ${localHits.joinToString(", ")}. This is not proof of a bypass.", "Check that these client flags only control presentation; the backend must independently authorize every protected API/content request.")
    val adMarkers = listOf("com.google.android.gms.ads", "com.google.ads", "com.applovin", "com.unity3d.ads", "com.facebook.ads", "com.ironsource", "com.chartboost")
    val adHits = adMarkers.filter { lower.contains(it) }
    addIf(adHits.isNotEmpty(), "AD SDK INVENTORY", "INFO", "Advertising SDK markers found", "Detected SDK families: ${adHits.joinToString(", ")}.", "Review consent, ad request configuration, test-device handling, data collection disclosures and server-side ad revenue validation where applicable.")
    val licenseMarkers = listOf("licensechecker", "licensing", "licensevalid", "checklicense", "googleplaylicensing")
    val licenseHits = licenseMarkers.filter { lower.contains(it) }
    addIf(licenseHits.isNotEmpty(), "LICENSE DESIGN", "INFO", "License-related code markers found", "Detected terms: ${licenseHits.joinToString(", ")}.", "Verify license decisions on a trusted server where possible; do not rely solely on a client boolean or locally stored flag.")
    val secretPatterns = listOf(Regex("(?i)AIza[0-9A-Za-z_-]{30,}"), Regex("(?i)sk_live_[0-9a-zA-Z]{16,}"), Regex("(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----"))
    val secretCount = secretPatterns.sumOf { it.findAll(text).count() }
    addIf(secretCount > 0, "SECRET EXPOSURE", "HIGH", "Potential embedded secret pattern detected", "$secretCount pattern match(es); values are deliberately not displayed or exported.", "Rotate any real exposed secret and move privileged credentials to a backend. Confirm each match manually to eliminate false positives.")
    if (findings.isEmpty()) findings.add(BillingAuditFinding("COVERAGE", "INFO", "No common billing or advertising indicators found", "No recognized markers were found in bounded DEX string inspection.", "Obfuscation, native code, dynamic loading and alternate SDKs can hide behavior. This is not a clean bill of health."))
    findings.add(BillingAuditFinding("COVERAGE", "INFO", "Static inspection boundaries", "$dexCount DEX file(s) inspected; strings only, no app execution or network requests.", "Use this as triage. Confirm all important behavior with source review, test builds, controlled runtime testing and backend logs."))
    return findings
}

@Composable
fun BillingSecurityAuditPanel(context: Context, packageName: String, apkPath: String?, modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    var findings by remember(packageName, apkPath) { mutableStateOf(emptyList<BillingAuditFinding>()) }
    var status by remember { mutableStateOf("Run a bounded static review of the selected APK.") }
    var busy by remember { mutableStateOf(false) }
    val testCases = listOf(
        "Pending purchase must not grant entitlement",
        "Duplicate purchase callback and token replay are idempotently rejected",
        "Wrong package name or product ID is rejected by backend",
        "Purchase token is verified with Google Play Developer API",
        "Refund, chargeback and revocation remove entitlement correctly",
        "Expired, paused, grace-period and account-hold states follow policy",
        "Account switching cannot transfer another user’s entitlement",
        "Offline mode fails closed for protected content and APIs",
        "Client-side premium flags cannot authorize protected backend requests",
        "Acknowledge/consume happens only after successful verification and fulfillment",
        "RTDN is authenticated, deduplicated and reconciled against Play Developer API",
        "Test and production package IDs, products and credentials are isolated"
    )
    val checks = remember(packageName) { context.getSharedPreferences("omni_billing_security_checks", Context.MODE_PRIVATE) }
    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri: Uri? ->
        if (uri != null) scope.launch {
            try {
                val payload = JSONObject().put("packageName", packageName).put("generatedAt", java.text.DateFormat.getDateTimeInstance().format(java.util.Date()))
                    .put("findings", JSONArray().apply { findings.forEach { put(JSONObject().put("category", it.category).put("severity", it.severity).put("title", it.title).put("evidence", it.evidence).put("recommendation", it.recommendation)) } })
                    .put("manualTestCases", JSONArray().apply { testCases.forEachIndexed { index, item -> put(JSONObject().put("test", item).put("recordedAsAttempted", checks.getBoolean("$packageName-$index", false))) } })
                withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(payload.toString(2)) } ?: error("Could not open export destination.") }
                status = "Security audit JSON exported. Attempted checks are operator records, not verified passes."
            } catch (e: Exception) { status = "Export failed: ${e.message}" }
        }
    }
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(9.dp)) {
        Text("BILLING • ADS • LICENSE SECURITY AUDIT", color = BillingAuditGreen, fontWeight = FontWeight.ExtraBold, fontSize = 12.sp)
        Text("Passive APK inspection plus a repeatable owner-authorized billing test matrix. No purchase is forged, no license is bypassed, and no third-party entitlement is changed.", color = BillingAuditAmber, fontSize = 10.sp)
        Button(onClick = { scope.launch { busy = true; try { findings = withContext(Dispatchers.IO) { require(!apkPath.isNullOrBlank()) { "Import/select an APK first." }; runBillingStaticAudit(File(apkPath)) }; status = "Static audit completed: ${findings.size} evidence item(s). Review each indicator."; } catch (e: Exception) { status = "Audit failed: ${e.message}" }; busy = false } }, enabled = !busy && !apkPath.isNullOrBlank(), modifier = Modifier.fillMaxWidth()) { Text(if (busy) "Inspecting APK…" else "Run billing / ads / license static audit") }
        if (findings.isNotEmpty()) {
            Text("STATIC FINDINGS", color = BillingAuditGreen, fontWeight = FontWeight.Bold, fontSize = 11.sp)
            findings.forEach { finding ->
                Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF18232D))) {
                    Column(Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("${finding.severity} • ${finding.category}", color = if (finding.severity == "HIGH") BillingAuditAmber else BillingAuditGreen, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                        Text(finding.title, color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        Text(finding.evidence, color = BillingAuditMuted, fontSize = 9.sp)
                        Text("NEXT: ${finding.recommendation}", color = BillingAuditMuted, fontSize = 9.sp)
                    }
                }
            }
        }
        Text("REPEATABLE PLAY BILLING SECURITY TEST MATRIX", color = BillingAuditGreen, fontWeight = FontWeight.Bold, fontSize = 11.sp)
        Text("Mark only after attempting the test in your own Play Console test track / backend. This app cannot independently confirm the outcome.", color = BillingAuditMuted, fontSize = 9.sp)
        testCases.forEachIndexed { index, test ->
            val key = "$packageName-$index"
            var attempted by remember(packageName, index) { mutableStateOf(checks.getBoolean(key, false)) }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Checkbox(checked = attempted, onCheckedChange = { attempted = it; checks.edit().putBoolean(key, it).apply() })
                Text(test, color = BillingAuditMuted, fontSize = 10.sp, modifier = Modifier.weight(1f).padding(top = 10.dp))
            }
        }
        OutlinedButton(onClick = { exportLauncher.launch("omni-billing-security-${packageName.substringAfterLast(".")}.json") }, modifier = Modifier.fillMaxWidth()) { Text("Export static findings + test matrix (JSON)") }
        Text("STATUS: $status", color = BillingAuditMuted, fontSize = 9.sp)
        Text("REAL GOOGLE PLAY VERIFICATION: requires your Play Console app, service-account credentials stored only on your backend, a purchase-token verification endpoint, idempotent entitlement storage and RTDN receiver. OMNI does not claim a live verification without those credentials and a real backend response.", color = BillingAuditAmber, fontSize = 9.sp)
    }
}