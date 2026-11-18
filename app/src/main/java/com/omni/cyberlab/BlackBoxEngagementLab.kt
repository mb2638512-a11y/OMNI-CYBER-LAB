package com.omni.cyberlab

import android.content.Context
import android.graphics.Paint
import android.graphics.pdf.PdfDocument
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.json.JSONArray
import org.json.JSONObject
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.net.URI
import java.util.Date

private val localDataChecks = listOf("Sensitive values are not stored in plaintext preferences", "Database files and backups follow app-private access controls", "Logs exclude credentials, tokens, personal data and payment details", "Clipboard use avoids copying secrets or marks sensitive clips appropriately", "Cache and temporary files do not retain sensitive records", "Shared/external storage contains no private app data", "Android backup and data-extraction rules match data sensitivity", "Screenshots and recent-app previews protect sensitive screens", "Local encryption keys use Android Keystore where required", "Logout/account switching clears or isolates user-specific local data")
private val networkChecks = listOf("All production API endpoints require HTTPS", "Cleartext traffic is disabled or narrowly justified", "TLS certificate validation uses platform trust checks", "No trust-all hostname verifier or permissive trust manager is present", "Sensitive data is not placed in URL query strings", "Authentication material is not logged or exposed in error messages", "Redirect behavior does not downgrade HTTPS or leak credentials", "API responses enforce authorization server-side for each object", "Security headers and cache directives are appropriate for sensitive responses", "Network failures and offline mode fail closed for protected operations")

private val billingLifecycleChecks = listOf("Purchase is verified by the trusted backend, not client UI state alone", "Pending purchases do not unlock paid entitlements prematurely", "Purchase acknowledgement and consumption follow product type", "Duplicate purchase callbacks are idempotent", "Restore purchases recovers only valid purchases for the signed-in account", "Refund and revocation events remove or adjust entitlements server-side", "Expired subscriptions stop granting access after the allowed grace period", "Grace period and account hold states follow documented policy", "Account switching does not transfer another user entitlement", "Product IDs, package name and purchase tokens are validated server-side", "Sandbox and production billing environments are separated", "Client tampering cannot create a server-confirmed paid entitlement")

private val blackBoxChecks = listOf(
    "Public attack-surface mapping: app links, exported components and documented API hosts",
    "Authentication and session lifecycle using client-provided test accounts",
    "Authorization boundaries with two or more client-owned test roles/accounts",
    "Input validation with non-destructive boundary and malformed-input cases",
    "Deep-link and intent handling, including untrusted parameter validation",
    "Local data exposure: logs, backups, clipboard, cache and shared storage",
    "Transport security: TLS configuration, cleartext policy and certificate handling",
    "API access control, object ownership and server-side entitlement enforcement",
    "Billing sandbox: pending, purchase, acknowledgement, refund and restore lifecycle",
    "Rate-limit and abuse-control assessment using low-volume agreed test requests",
    "Tamper and integrity assessment using client-approved modified test builds",
    "Detection and response review: whether test events are logged and alerted",
)

@Composable
fun BlackBoxEngagementLab(context: Context, packageName: String, modifier: Modifier = Modifier) {
    val registryPrefs = remember(context, packageName) { context.getSharedPreferences("omni_blackbox_registry_$packageName", Context.MODE_PRIVATE) }
    var activeEngagementId by remember(packageName) { mutableStateOf(registryPrefs.getString("active_engagement_id", "default") ?: "default") }
    var engagementRegistryJson by remember(packageName) { mutableStateOf(registryPrefs.getString("engagement_registry", "[]") ?: "[]") }
    var newEngagementTitle by remember(packageName) { mutableStateOf("Mobile application security assessment") }
    val prefs = remember(context, packageName, activeEngagementId) {
        if (activeEngagementId == "default") context.getSharedPreferences("omni_blackbox_$packageName", Context.MODE_PRIVATE)
        else context.getSharedPreferences("omni_blackbox_${packageName}_$activeEngagementId", Context.MODE_PRIVATE)
    }
    val scope = rememberCoroutineScope()
    var target by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("target", packageName) ?: packageName) }
    var clientName by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("client_name", "") ?: "") }
    var engagementName by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("engagement_name", "Mobile application security assessment") ?: "Mobile application security assessment") }
    var engagementStatus by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("engagement_status", "PLANNED") ?: "PLANNED") }
    var engagementReference by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("engagement_reference", "") ?: "") }
    var engagementSnapshotsJson by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("engagement_snapshots", "[]") ?: "[]") }
    var billingCase by remember(packageName, activeEngagementId) { mutableIntStateOf(0) }
    var billingOutcome by remember(packageName, activeEngagementId) { mutableStateOf("NOT TESTED") }
    var billingEvidence by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var billingJson by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("billing_lifecycle_records", "[]") ?: "[]") }
    var apiHosts by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("hosts", "") ?: "") }
    var exclusions by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("exclusions", "") ?: "") }
    var testWindow by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("window", "Client-agreed schedule") ?: "Client-agreed schedule") }
    var authorized by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getBoolean("authorized", false)) }
    var notes by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("notes", "") ?: "") }
    var checked by remember(packageName, activeEngagementId) { mutableStateOf(blackBoxChecks.indices.filter { prefs.getBoolean("check_$it", false) }.toSet()) }
    var status by remember { mutableStateOf("Define the client scope before starting an engagement.") }
    var endpoint by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("probe_endpoint", "") ?: "") }
    var probeMethod by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("probe_method", "GET") ?: "GET") }
    var probeBusy by remember { mutableStateOf(false) }
    var probeResult by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("probe_result", "") ?: "") }
    var probeHistoryJson by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("probe_history", "[]") ?: "[]") }
    var findingTitle by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var findingSeverity by remember(packageName, activeEngagementId) { mutableStateOf("MEDIUM") }
    var findingCvss by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var findingCwe by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var findingSteps by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var findingImpact by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var findingFix by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var findingsJson by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("findings_json", "[]") ?: "[]") }
    var matrixResource by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var matrixActor by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var matrixExpected by remember(packageName, activeEngagementId) { mutableStateOf("DENY") }
    var matrixObserved by remember(packageName, activeEngagementId) { mutableStateOf("NOT TESTED") }
    var matrixEvidence by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var matrixJson by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("authorization_matrix", "[]") ?: "[]") }
    val sessionChecks = listOf("Token storage: secrets not exposed in logs, clipboard or world-readable files", "Logout invalidation: old session no longer accepted by client backend", "Session expiry: expired access token is rejected", "Refresh lifecycle: refresh token rotation and expiry behavior", "Refresh replay: previously rotated token is rejected", "Revocation: password reset or account disable invalidates sessions as designed", "Account switching: prior account data is not shown after switching users", "Concurrent sessions: device/session management follows product policy", "Authentication errors: responses do not disclose sensitive account details", "Session persistence: app restart behavior matches documented policy", "Sensitive screens: app switcher/background exposure is controlled", "Re-authentication: sensitive actions require fresh authentication where required")
    var sessionCase by remember(packageName, activeEngagementId) { mutableStateOf(0) }
    var sessionOutcome by remember(packageName, activeEngagementId) { mutableStateOf("NOT TESTED") }
    var sessionEvidence by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var sessionRecordsJson by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("session_security_records", "[]") ?: "[]") }
    var localDataCase by remember(packageName, activeEngagementId) { mutableIntStateOf(0) }
    var localDataOutcome by remember(packageName, activeEngagementId) { mutableStateOf("NOT TESTED") }
    var localDataEvidence by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var localDataJson by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("local_data_records", "[]") ?: "[]") }
    var networkCase by remember(packageName, activeEngagementId) { mutableIntStateOf(0) }
    var networkOutcome by remember(packageName, activeEngagementId) { mutableStateOf("NOT TESTED") }
    var networkEvidence by remember(packageName, activeEngagementId) { mutableStateOf("") }
    var networkJson by remember(packageName, activeEngagementId) { mutableStateOf(prefs.getString("network_security_records", "[]") ?: "[]") }
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri: Uri? ->
        if (uri != null) {
            val payload = JSONObject()
                .put("reportType", "OMNI CYBER LAB - Black-box penetration test plan")
                .put("packageName", packageName)
                .put("target", target)
                .put("allowedApiHosts", apiHosts)
                .put("excludedAssets", exclusions)
                .put("testWindow", testWindow)
                .put("authorizationConfirmedByOperator", authorized)
                .put("generatedAt", DateFormat.getDateTimeInstance().format(Date()))
                .put("completedChecks", JSONArray(checked.sorted().map { blackBoxChecks[it] }))
                .put("remainingChecks", JSONArray(blackBoxChecks.indices.filter { it !in checked }.map { blackBoxChecks[it] }))
                .put("operatorNotes", notes)
                .put("lastEndpointProbe", if (probeResult.isBlank()) JSONObject.NULL else JSONObject(probeResult))
                .put("endpointProbeHistory", JSONArray(probeHistoryJson))
                .put("findings", JSONArray(findingsJson))
                .put("authorizationMatrix", JSONArray(matrixJson))
                .put("sessionSecurityTests", JSONArray(sessionRecordsJson))
                .put("localDataSecurityTests", JSONArray(localDataJson))
                .put("networkSecurityTests", JSONArray(networkJson))
                .put("clientName", clientName)
                .put("engagementName", engagementName)
                .put("engagementStatus", engagementStatus)
                .put("engagementReference", engagementReference)
                .put("engagementSnapshots", JSONArray(engagementSnapshotsJson))
                .put("billingLifecycleTests", JSONArray(billingJson))
                .put("limitations", "This is a scoped manual test record, not proof of exploitability or a passed security assessment.")
            scope.launch {
                try { context.contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(payload.toString(2)) } ?: error("Cannot open export destination."); status = "Engagement plan exported." }
                catch (e: Exception) { status = "Export failed: ${e.message}" }
            }
        }
    }
    val pdfExport = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri: Uri? ->
        if (uri != null) {
            try {
                val reportText = buildString {
                    appendLine("OMNI CYBER LAB — CLIENT SECURITY ASSESSMENT")
                    appendLine("Client: $clientName")
                    appendLine("Engagement: $engagementName")
                    appendLine("Reference: $engagementReference")
                    appendLine("Status: $engagementStatus")
                    appendLine("Saved engagement checkpoints: ${JSONArray(engagementSnapshotsJson).length()}")
                    appendLine("Target: $target")
                    appendLine("Package: $packageName")
                    appendLine("Generated: ${DateFormat.getDateTimeInstance().format(Date())}")
                    appendLine("Authorization confirmed by operator: $authorized")
                    appendLine()
                    appendLine("SCOPE")
                    appendLine("Allowed API hosts: $apiHosts")
                    appendLine("Excluded assets: $exclusions")
                    appendLine("Test window / rate limits: $testWindow")
                    appendLine()
                    appendLine("ATTACK SURFACE COVERAGE: ${checked.size}/${blackBoxChecks.size}")
                    checked.sorted().forEach { appendLine("COMPLETED CHECK: ${blackBoxChecks[it]}") }
                    blackBoxChecks.indices.filter { it !in checked }.forEach { appendLine("NOT RECORDED: ${blackBoxChecks[it]}") }
                    appendLine()
                    appendLine("FINDINGS")
                    val findings = JSONArray(findingsJson)
                    if (findings.length() == 0) appendLine("No finding records saved.")
                    for (i in 0 until findings.length()) {
                        val f = findings.optJSONObject(i) ?: continue
                        appendLine("${i + 1}. [${f.optString("severity")}] ${f.optString("title")}")
                        appendLine("Workflow: ${f.optString("workflowStatus", "OPEN")} | CVSS: ${f.opt("cvssBaseScore") ?: "Not supplied"} | CWE: ${f.optString("cweReference", "Not supplied")}")
                        appendLine("Reproduction: ${f.optString("reproduction")}")
                        appendLine("Impact / evidence: ${f.optString("impactEvidence")}")
                        appendLine("Remediation: ${f.optString("remediation")}")
                        appendLine("Verification: ${f.optString("status", "UNVERIFIED")}")
                    }
                    appendLine()
                    appendLine("TEST RECORD COUNTS")
                    appendLine("API authorization matrix: ${JSONArray(matrixJson).length()}")
                    appendLine("Authentication/session: ${JSONArray(sessionRecordsJson).length()}")
                    appendLine("Local data: ${JSONArray(localDataJson).length()}")
                    appendLine("Network security: ${JSONArray(networkJson).length()}")
                    appendLine("Billing lifecycle: ${JSONArray(billingJson).length()}")
                    appendLine("Endpoint probe history: ${JSONArray(probeHistoryJson).length()}")
                    appendLine()
                    appendLine("OPERATOR NOTES")
                    appendLine(notes)
                    appendLine()
                    appendLine("LIMITATIONS")
                    appendLine("This report reflects operator-entered records and configured checks. It is not an independent certification, automated penetration-test result, or proof that untested areas are secure.")
                    appendLine("Findings and workflow statuses require evidence-backed review. A status of RETEST RECORDED or CLOSED is not independently verified by this app.")
                }
                val paint = Paint().apply { textSize = 9f; isAntiAlias = true }
                val lines = reportText.lines().flatMap { line ->
                    if (line.isBlank()) listOf("") else {
                        val words = line.split(Regex("\\s+"))
                        val wrapped = mutableListOf<String>()
                        var current = ""
                        words.forEach { word ->
                            if (current.isNotEmpty() && current.length + word.length + 1 > 96) { wrapped.add(current); current = word }
                            else current = if (current.isEmpty()) word else current + " " + word
                        }
                        if (current.isNotEmpty()) wrapped.add(current)
                        wrapped
                    }
                }
                val pdf = PdfDocument()
                var pageNo = 1
                var lineIndex = 0
                while (lineIndex < lines.size) {
                    val page = pdf.startPage(PdfDocument.PageInfo.Builder(595, 842, pageNo).create())
                    var y = 40f
                    while (lineIndex < lines.size && y < 805f) {
                        page.canvas.drawText(lines[lineIndex], 36f, y, paint)
                        y += 14f
                        lineIndex++
                    }
                    pdf.finishPage(page)
                    pageNo++
                }
                val output = context.contentResolver.openOutputStream(uri) ?: error("Cannot open PDF destination")
                output.use { pdf.writeTo(it) }
                pdf.close()
                status = "Client assessment PDF exported."
            } catch (e: Exception) { status = "PDF export failed: ${e.message}" }
        }
    }
    Column(modifier.fillMaxWidth().padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
        Text("CLIENT ENGAGEMENT MANAGER", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        Text("Each engagement has its own local workspace and assessment records. Switching workspaces does not merge their findings or evidence.", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(newEngagementTitle, { newEngagementTitle = it }, label = { Text("New engagement title") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedButton(onClick = {
            val id = "eng_${System.currentTimeMillis()}"
            val registry = runCatching { JSONArray(engagementRegistryJson) }.getOrElse { JSONArray() }
            registry.put(JSONObject().put("id", id).put("title", newEngagementTitle.trim().ifBlank { "New security assessment" }).put("createdAt", DateFormat.getDateTimeInstance().format(Date())))
            engagementRegistryJson = registry.toString()
            registryPrefs.edit().putString("engagement_registry", engagementRegistryJson).putString("active_engagement_id", id).apply()
            val nextPrefs = context.getSharedPreferences("omni_blackbox_${packageName}_$id", Context.MODE_PRIVATE)
            nextPrefs.edit().putString("engagement_name", newEngagementTitle.trim().ifBlank { "New security assessment" }).putString("engagement_status", "PLANNED").putString("target", packageName).apply()
            activeEngagementId = id
            status = "New isolated engagement workspace created."
        }, enabled = newEngagementTitle.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Create separate engagement workspace") }
        val registryItems = runCatching { JSONArray(engagementRegistryJson) }.getOrElse { JSONArray() }
        Text("WORKSPACES • ${registryItems.length() + 1}", style = MaterialTheme.typography.labelLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            FilterChip(selected = activeEngagementId == "default", onClick = { activeEngagementId = "default"; registryPrefs.edit().putString("active_engagement_id", "default").apply() }, label = { Text("Original workspace") })
            for (index in 0 until registryItems.length()) {
                val item = registryItems.optJSONObject(index) ?: continue
                val id = item.optString("id")
                FilterChip(selected = activeEngagementId == id, onClick = { activeEngagementId = id; registryPrefs.edit().putString("active_engagement_id", id).apply() }, label = { Text(item.optString("title").take(18)) })
            }
        }
        Text("Active workspace: ${if (activeEngagementId == "default") "Original workspace" else activeEngagementId}", style = MaterialTheme.typography.labelSmall)
        Divider()
        Text("CLIENT ENGAGEMENT WORKSPACE", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.titleSmall)
        Text("Organize assessments by client and engagement reference. Do not store client secrets or personal contact details here.", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(clientName, { clientName = it; prefs.edit().putString("client_name", it).apply() }, label = { Text("Client / organization") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(engagementName, { engagementName = it; prefs.edit().putString("engagement_name", it).apply() }, label = { Text("Engagement title") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(engagementReference, { engagementReference = it; prefs.edit().putString("engagement_reference", it).apply() }, label = { Text("PO / engagement reference (optional)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) { listOf("PLANNED", "ACTIVE", "PAUSED", "COMPLETED", "CLOSED").forEach { value -> FilterChip(selected = engagementStatus == value, onClick = { engagementStatus = value; prefs.edit().putString("engagement_status", value).apply() }, label = { Text(value) }) } }
        OutlinedButton(onClick = {
            if (!authorized) {
                status = "Confirm client authorization before saving an engagement checkpoint."
            } else {
                val snapshot = JSONObject()
                    .put("id", "ENG-${System.currentTimeMillis()}")
                    .put("savedAt", DateFormat.getDateTimeInstance().format(Date()))
                    .put("clientName", clientName)
                    .put("engagementName", engagementName)
                    .put("engagementReference", engagementReference)
                    .put("engagementStatus", engagementStatus)
                    .put("target", target)
                    .put("packageName", packageName)
                    .put("allowedApiHosts", apiHosts)
                    .put("excludedAssets", exclusions)
                    .put("testWindow", testWindow)
                    .put("authorizationConfirmed", authorized)
                    .put("coverageCompleted", checked.size)
                    .put("coverageTotal", blackBoxChecks.size)
                    .put("findingCount", JSONArray(findingsJson).length())
                    .put("apiAuthorizationRecords", JSONArray(matrixJson).length())
                    .put("sessionSecurityRecords", JSONArray(sessionRecordsJson).length())
                    .put("localDataRecords", JSONArray(localDataJson).length())
                    .put("networkSecurityRecords", JSONArray(networkJson).length())
                    .put("billingRecords", JSONArray(billingJson).length())
                    .put("endpointProbeRecords", JSONArray(probeHistoryJson).length())
                    .put("operatorNotes", notes)
                    .put("findings", JSONArray(findingsJson))
                    .put("authorizationMatrix", JSONArray(matrixJson))
                    .put("sessionSecurityTests", JSONArray(sessionRecordsJson))
                    .put("localDataSecurityTests", JSONArray(localDataJson))
                    .put("networkSecurityTests", JSONArray(networkJson))
                    .put("billingLifecycleTests", JSONArray(billingJson))
                    .put("endpointProbeHistory", JSONArray(probeHistoryJson))
                    .put("completedChecks", JSONArray(checked.sorted().map { blackBoxChecks[it] }))
                val history = runCatching { JSONArray(engagementSnapshotsJson) }.getOrElse { JSONArray() }
                history.put(snapshot)
                val bounded = JSONArray()
                for (index in (history.length() - 20).coerceAtLeast(0) until history.length()) bounded.put(history.getJSONObject(index))
                engagementSnapshotsJson = bounded.toString()
                prefs.edit().putString("engagement_snapshots", engagementSnapshotsJson).apply()
                status = "Engagement checkpoint saved. Existing records remain unchanged."
            }
        }, enabled = authorized, modifier = Modifier.fillMaxWidth()) { Text("Save engagement checkpoint") }
        val engagementHistory = runCatching { JSONArray(engagementSnapshotsJson) }.getOrElse { JSONArray() }
        Text("ENGAGEMENT CHECKPOINT HISTORY • ${engagementHistory.length()} / 20", style = MaterialTheme.typography.labelLarge)
        if (engagementHistory.length() > 0) {
            for (index in (engagementHistory.length() - 3).coerceAtLeast(0) until engagementHistory.length()) {
                val checkpoint = engagementHistory.optJSONObject(index) ?: continue
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(checkpoint.optString("engagementName"), style = MaterialTheme.typography.bodyMedium)
                        Text("${checkpoint.optString("clientName")} • ${checkpoint.optString("engagementReference")} • ${checkpoint.optString("engagementStatus")}", style = MaterialTheme.typography.labelSmall)
                        Text("Saved: ${checkpoint.optString("savedAt")} • Coverage: ${checkpoint.optInt("coverageCompleted")}/${checkpoint.optInt("coverageTotal")} • Findings: ${checkpoint.optInt("findingCount")}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            Text("Checkpoints are immutable snapshots of the current local workspace, not separate isolated engagement databases. Latest 20 are retained on this device.", style = MaterialTheme.typography.labelSmall)
        } else Text("No saved engagement checkpoints yet.", style = MaterialTheme.typography.bodySmall)
        if (engagementHistory.length() >= 2) {
            val older = engagementHistory.optJSONObject(engagementHistory.length() - 2)
            val newer = engagementHistory.optJSONObject(engagementHistory.length() - 1)
            if (older != null && newer != null) {
                val olderCoverage = older.optInt("coverageCompleted")
                val newerCoverage = newer.optInt("coverageCompleted")
                val olderFindings = older.optInt("findingCount")
                val newerFindings = newer.optInt("findingCount")
                val olderTitles = (0 until (older.optJSONArray("findings")?.length() ?: 0)).mapNotNull { older.optJSONArray("findings")?.optJSONObject(it)?.optString("title")?.takeIf { title -> title.isNotBlank() } }.toSet()
                val newTitles = (0 until (newer.optJSONArray("findings")?.length() ?: 0)).mapNotNull { newer.optJSONArray("findings")?.optJSONObject(it)?.optString("title")?.takeIf { title -> title.isNotBlank() } }.toSet()
                val addedTitles = newTitles - olderTitles
                val absentTitles = olderTitles - newTitles
                val recordKeys = listOf("apiAuthorizationRecords", "sessionSecurityRecords", "localDataRecords", "networkSecurityRecords", "billingRecords", "endpointProbeRecords")
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("LATEST CHECKPOINT COMPARISON", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
                        Text("${older.optString("savedAt")} → ${newer.optString("savedAt")}", style = MaterialTheme.typography.labelSmall)
                        Text("Coverage: $olderCoverage → $newerCoverage (${if (newerCoverage - olderCoverage >= 0) "+" else ""}${newerCoverage - olderCoverage}) / ${newer.optInt("coverageTotal")}", style = MaterialTheme.typography.bodySmall)
                        Text("Finding records: $olderFindings → $newerFindings (${if (newerFindings - olderFindings >= 0) "+" else ""}${newerFindings - olderFindings})", style = MaterialTheme.typography.bodySmall)
                        recordKeys.forEach { key -> Text("$key: ${older.optInt(key)} → ${newer.optInt(key)} (${newer.optInt(key) - older.optInt(key)})", style = MaterialTheme.typography.bodySmall) }
                        Text("Finding titles newly present: ${addedTitles.size} • no longer present: ${absentTitles.size}", style = MaterialTheme.typography.bodySmall)
                        addedTitles.take(5).forEach { Text("NEW: $it", style = MaterialTheme.typography.labelSmall) }
                        absentTitles.take(5).forEach { Text("NOT IN LATEST SNAPSHOT: $it", style = MaterialTheme.typography.labelSmall) }
                        Text("Comparison uses saved record counts and finding titles only. Missing from a snapshot does not prove a vulnerability was fixed; snapshots may represent different scope or data entry.", style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }
        Divider()
        Text("BLIND / BLACK-BOX PENETRATION TEST",color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.titleSmall)
        Text("Start with only the client-provided app and public-facing information. Keep the test low-noise where agreed, record evidence, and do not assume hidden assets are in scope.", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(target, { target = it; prefs.edit().putString("target", it).apply() }, label = { Text("Target package / app / domain") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(apiHosts, { apiHosts = it; prefs.edit().putString("hosts", it).apply() }, label = { Text("Allowed API hosts (one per line)") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        OutlinedTextField(exclusions, { exclusions = it; prefs.edit().putString("exclusions", it).apply() }, label = { Text("Excluded hosts, accounts or functions") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        OutlinedTextField(testWindow, { testWindow = it; prefs.edit().putString("window", it).apply() }, label = { Text("Testing window / rate limits") }, modifier = Modifier.fillMaxWidth())
        Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            Checkbox(checked = authorized, onCheckedChange = { authorized = it; prefs.edit().putBoolean("authorized", it).apply() })
            Text("Client authorization and scope have been verified", style = MaterialTheme.typography.bodySmall)
        }
        Text("ATTACK-SURFACE TEST MATRIX (${checked.size}/${blackBoxChecks.size})", style = MaterialTheme.typography.labelLarge)
        blackBoxChecks.forEachIndexed { index, label ->
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Checkbox(checked = index in checked, onCheckedChange = { value ->
                    checked = if (value) checked + index else checked - index
                    prefs.edit().putBoolean("check_$index", value).apply()
                })
                Text(label, style = MaterialTheme.typography.bodySmall)
            }
        }
        Divider()
        Text("LIVE SCOPED HTTPS ENDPOINT PROBE", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        Text("Sends one GET or HEAD request to an exact allowlisted HTTPS hostname. Redirects are not followed; response bodies are hashed but not saved. No fuzzing, credential guessing or state-changing methods.", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(endpoint, { endpoint = it; prefs.edit().putString("probe_endpoint", it).apply() }, label = { Text("HTTPS endpoint URL") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = probeMethod == "GET", onClick = { probeMethod = "GET"; prefs.edit().putString("probe_method", "GET").apply() }, label = { Text("GET") })
            FilterChip(selected = probeMethod == "HEAD", onClick = { probeMethod = "HEAD"; prefs.edit().putString("probe_method", "HEAD").apply() }, label = { Text("HEAD") })
        }
        Button(onClick = {
            val allowed = apiHosts.lines().map { it.trim().lowercase() }.filter { it.isNotBlank() }.map { raw -> runCatching { URI(if (raw.contains("://")) raw else "https://$raw").host?.lowercase() }.getOrNull() }.filterNotNull().toSet()
            probeBusy = true
            scope.launch {
                try {
                    val result = runScopedEndpointProbe(endpoint, allowed, probeMethod)
                    probeResult = result.toJson().toString(2)
                    val history = runCatching { JSONArray(probeHistoryJson) }.getOrElse { JSONArray() }
                    val previous = if (history.length() > 0) history.optJSONObject(history.length() - 1) else null
                    val certChanged = previous != null && previous.optString("certificateSha256").isNotBlank() && result.certificateSha256.isNotBlank() && previous.optString("certificateSha256") != result.certificateSha256
                    val record = result.toJson().put("checkedAt", DateFormat.getDateTimeInstance().format(Date())).put("certificateChangedSincePrevious", certChanged)
                    history.put(record)
                    val trimmed = JSONArray()
                    for (i in maxOf(0, history.length() - 10) until history.length()) trimmed.put(history.get(i))
                    probeHistoryJson = trimmed.toString()
                    prefs.edit().putString("probe_result", probeResult).putString("probe_history", probeHistoryJson).apply()
                    status = "Scoped endpoint probe complete: HTTP ${result.statusCode} in ${result.durationMs} ms." + if (certChanged) " REVIEW: certificate fingerprint changed since previous probe." else ""
                } catch (e: Exception) { status = "Probe not completed: ${e.message ?: "unknown error"}" }
                finally { probeBusy = false }
            }
        }, enabled = authorized && !probeBusy && endpoint.isNotBlank() && apiHosts.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text(if (probeBusy) "Testing…" else "Run one scoped HTTPS check") }
        if (probeResult.isNotBlank()) {
            val p = runCatching { JSONObject(probeResult) }.getOrNull()
            if (p != null) {
                Text("Last result: HTTP ${p.optInt("statusCode")} • ${p.optLong("durationMs")} ms", style = MaterialTheme.typography.bodyMedium)
                Text("TLS: ${p.optString("tlsProtocol")} • ${p.optString("tlsCipher")}", style = MaterialTheme.typography.bodySmall)
                Text("Certificate SHA-256: ${p.optString("certificateSha256")}", style = MaterialTheme.typography.labelSmall)
                Text("Certificate valid now: ${p.optBoolean("certificateValidNow")} • Days remaining: ${p.optLong("certificateDaysRemaining")}", style = MaterialTheme.typography.bodySmall)
                Text("Valid from: ${p.optString("certificateNotBefore")} • Expires: ${p.optString("certificateNotAfter")}", style = MaterialTheme.typography.labelSmall)
                Text("Security headers: ${p.optJSONObject("securityHeaders")?.length() ?: 0} observed • Body bytes hashed: ${p.optInt("bodyBytesRead")}", style = MaterialTheme.typography.bodySmall)
                val observedHeaders = p.optJSONObject("securityHeaders")
                listOf("Strict-Transport-Security", "X-Content-Type-Options", "Content-Security-Policy", "Referrer-Policy", "Cache-Control").forEach { header ->
                    val value = observedHeaders?.optString(header).orEmpty()
                    Text("${if (value.isBlank()) "REVIEW • not observed" else "OBSERVED"} — $header${if (value.isNotBlank()) ": ${value.take(160)}" else ""}", style = MaterialTheme.typography.labelSmall)
                }
                val hsts = observedHeaders?.optString("Strict-Transport-Security").orEmpty()
                val csp = observedHeaders?.optString("Content-Security-Policy").orEmpty()
                val xcto = observedHeaders?.optString("X-Content-Type-Options").orEmpty()
                val hstsAge = Regex("max-age\\s*=\\s*(\\d+)", RegexOption.IGNORE_CASE).find(hsts)?.groupValues?.getOrNull(1)?.toLongOrNull()
                Text("PASSIVE HEADER REVIEW", style = MaterialTheme.typography.labelLarge)
                val headerReviews = buildList {
                    if (hsts.isBlank()) add("REVIEW • HSTS was not observed on this response.")
                    else if (hstsAge == null || hstsAge < 15552000L) add("REVIEW • HSTS max-age is missing or below the six-month baseline; assess deployment policy.")
                    if (csp.isBlank()) add("REVIEW • CSP was not observed; confirm whether this endpoint serves browser-rendered content.")
                    else {
                        if (Regex("unsafe-inline", RegexOption.IGNORE_CASE).containsMatchIn(csp)) add("REVIEW • CSP contains unsafe-inline; assess whether nonces or hashes can replace it.")
                        if (Regex("unsafe-eval", RegexOption.IGNORE_CASE).containsMatchIn(csp)) add("REVIEW • CSP contains unsafe-eval; assess whether dynamic evaluation is required.")
                        if (Regex("(?:^|;)\\s*default-src\\s+\\*", RegexOption.IGNORE_CASE).containsMatchIn(csp)) add("REVIEW • CSP default-src uses a wildcard source.")
                    }
                    if (!xcto.equals("nosniff", true)) add("REVIEW • X-Content-Type-Options is not observed as nosniff.")
                    if (isEmpty()) add("No basic header review signals were raised by these heuristics.")
                }
                headerReviews.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
                Text("Heuristic observations only: header policy depends on endpoint role, browser exposure and the client security standard.", style = MaterialTheme.typography.labelSmall)
                if (!p.optBoolean("certificateValidNow")) Text("REVIEW • peer certificate is not currently valid according to device clock.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                else if (p.optLong("certificateDaysRemaining") in 0L..30L) Text("REVIEW • peer certificate expires within 30 days.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
        }
        Text("This probe validates reachability and records response metadata; it does not prove an endpoint is vulnerable or secure.", style = MaterialTheme.typography.labelSmall)
        val probeHistory = runCatching { JSONArray(probeHistoryJson) }.getOrElse { JSONArray() }
        Text("PROBE HISTORY • ${probeHistory.length()} / 10", style = MaterialTheme.typography.labelLarge)
        if (probeHistory.length() > 0) {
            val recent = probeHistory.optJSONObject(probeHistory.length() - 1)
            if (recent != null) {
                Text("Latest: ${recent.optString("checkedAt")} • HTTP ${recent.optInt("statusCode")}", style = MaterialTheme.typography.bodySmall)
                if (recent.optBoolean("certificateChangedSincePrevious")) Text("Certificate fingerprint changed since previous probe — review certificate rotation and deployment records.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            Text("Saved history includes status, latency, certificate fingerprint and header observations. Changes are review signals, not automatic attack or compromise findings.", style = MaterialTheme.typography.labelSmall)
        } else Text("No endpoint probe history yet.", style = MaterialTheme.typography.bodySmall)
        Divider()
        Divider()
        Text("API AUTHORIZATION MATRIX", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        Text("Use only client-owned test accounts and records. Compare expected access with observed responses; do not enumerate or modify other users’ data.", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(matrixResource, { matrixResource = it }, label = { Text("API route / resource / record ID (test data only)") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(matrixActor, { matrixActor = it }, label = { Text("Actor role / test account label") }, modifier = Modifier.fillMaxWidth())
        Text("Expected access", style = MaterialTheme.typography.labelMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("ALLOW", "DENY").forEach { value -> FilterChip(selected = matrixExpected == value, onClick = { matrixExpected = value }, label = { Text(value) }) }
        }
        Text("Observed result", style = MaterialTheme.typography.labelMedium)
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            listOf("NOT TESTED", "ALLOWED", "DENIED", "UNEXPECTED ALLOW", "UNEXPECTED DENY", "ERROR").chunked(2).forEach { pair ->
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) { pair.forEach { value -> FilterChip(selected = matrixObserved == value, onClick = { matrixObserved = value }, label = { Text(value) }) } }
            }
        }
        OutlinedTextField(matrixEvidence, { matrixEvidence = it }, label = { Text("Evidence reference / response code / notes") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        Button(onClick = {
            val arr = runCatching { JSONArray(matrixJson) }.getOrElse { JSONArray() }
            val mismatch = (matrixExpected == "DENY" && matrixObserved == "ALLOWED") || (matrixExpected == "ALLOW" && matrixObserved == "DENIED")
            arr.put(JSONObject().put("id", "AC-${System.currentTimeMillis()}").put("resource", matrixResource.trim()).put("actorRole", matrixActor.trim()).put("expectedAccess", matrixExpected).put("observedResult", matrixObserved).put("accessExpectationMismatch", mismatch).put("evidence", matrixEvidence.trim()).put("recordedAt", DateFormat.getDateTimeInstance().format(Date())).put("status", if (matrixObserved == "NOT TESTED") "NOT TESTED" else "OPERATOR RECORDED • NEEDS REVIEW"))
            val bounded = JSONArray()
            for (index in (arr.length() - 100).coerceAtLeast(0) until arr.length()) bounded.put(arr.getJSONObject(index))
            matrixJson = bounded.toString()
            prefs.edit().putString("authorization_matrix", matrixJson).apply()
            matrixResource = ""; matrixEvidence = ""; matrixObserved = "NOT TESTED"
            status = if (mismatch) "Access expectation mismatch recorded. Reproduce and review before reporting a vulnerability." else "Authorization test case saved locally."
        }, enabled = authorized && matrixResource.isNotBlank() && matrixActor.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Save authorization test case") }
        val matrixRecords = runCatching { JSONArray(matrixJson) }.getOrElse { JSONArray() }
        Text("Saved access-control cases: ${matrixRecords.length()}", style = MaterialTheme.typography.bodyMedium)
        val mismatchCount = (0 until matrixRecords.length()).count { matrixRecords.optJSONObject(it)?.optBoolean("accessExpectationMismatch", false) == true }
        Text("Triage summary: $mismatchCount expected/observed mismatches • ${matrixRecords.length() - mismatchCount} other records", style = MaterialTheme.typography.labelSmall)
        if (matrixRecords.length() > 0) {
            val last = matrixRecords.optJSONObject(matrixRecords.length() - 1)
            if (last != null) Text("Latest: ${last.optString("actorRole")} • ${last.optString("expectedAccess")} → ${last.optString("observedResult")} • ${last.optString("status")}", style = MaterialTheme.typography.bodySmall)
            Text("Expectation mismatch is a triage signal only; confirm with repeatable evidence and server-side context.", style = MaterialTheme.typography.labelSmall)
        }
        Divider()
        Text("AUTHENTICATION & SESSION SECURITY LAB", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        Text("Manual checks for client-owned test accounts. Do not paste real tokens, passwords or secrets into evidence notes; use redacted references only.", style = MaterialTheme.typography.bodySmall)
        Text("Test case ${sessionCase + 1} of ${sessionChecks.size}", style = MaterialTheme.typography.labelMedium)
        Text(sessionChecks[sessionCase], style = MaterialTheme.typography.bodyMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedButton(onClick = { sessionCase = (sessionCase - 1).coerceAtLeast(0); sessionOutcome = "NOT TESTED"; sessionEvidence = "" }, enabled = sessionCase > 0) { Text("Previous") }
            OutlinedButton(onClick = { sessionCase = (sessionCase + 1).coerceAtMost(sessionChecks.lastIndex); sessionOutcome = "NOT TESTED"; sessionEvidence = "" }, enabled = sessionCase < sessionChecks.lastIndex) { Text("Next") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf("NOT TESTED", "PASS", "FAIL", "NEEDS REVIEW").forEach { value -> FilterChip(selected = sessionOutcome == value, onClick = { sessionOutcome = value }, label = { Text(value) }) }
        }
        OutlinedTextField(sessionEvidence, { sessionEvidence = it }, label = { Text("Redacted evidence reference / notes") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        Button(onClick = {
            val records = runCatching { JSONArray(sessionRecordsJson) }.getOrElse { JSONArray() }
            records.put(JSONObject().put("id", "SS-${System.currentTimeMillis()}").put("testCase", sessionChecks[sessionCase]).put("operatorOutcome", sessionOutcome).put("evidenceReference", sessionEvidence.trim()).put("recordedAt", DateFormat.getDateTimeInstance().format(Date())).put("status", "OPERATOR RECORDED • NOT INDEPENDENTLY VERIFIED"))
            val bounded = JSONArray()
            for (index in (records.length() - 100).coerceAtLeast(0) until records.length()) bounded.put(records.getJSONObject(index))
            sessionRecordsJson = bounded.toString()
            prefs.edit().putString("session_security_records", sessionRecordsJson).apply()
            sessionEvidence = ""
            status = "Session security observation saved locally. Verify with repeatable client-approved tests."
        }, enabled = authorized && sessionOutcome != "NOT TESTED", modifier = Modifier.fillMaxWidth()) { Text("Save session test result") }
        val sessionRecords = runCatching { JSONArray(sessionRecordsJson) }.getOrElse { JSONArray() }
        Text("Saved session observations: ${sessionRecords.length()}", style = MaterialTheme.typography.bodyMedium)
        val sessionPass = (0 until sessionRecords.length()).count { sessionRecords.optJSONObject(it)?.optString("operatorOutcome") == "PASS" }
        val sessionFail = (0 until sessionRecords.length()).count { sessionRecords.optJSONObject(it)?.optString("operatorOutcome") == "FAIL" }
        val sessionReview = (0 until sessionRecords.length()).count { sessionRecords.optJSONObject(it)?.optString("operatorOutcome") == "NEEDS REVIEW" }
        Text("Recorded outcomes: $sessionPass PASS • $sessionFail FAIL • $sessionReview NEEDS REVIEW", style = MaterialTheme.typography.labelSmall)
        if (sessionRecords.length() > 0) {
            val latestSession = sessionRecords.optJSONObject(sessionRecords.length() - 1)
            if (latestSession != null) Text("Latest: ${latestSession.optString("operatorOutcome")} • ${latestSession.optString("testCase")}", style = MaterialTheme.typography.bodySmall)
        }
        Text("This module records manual observations only. It does not capture, replay, revoke or modify authentication tokens.", style = MaterialTheme.typography.labelSmall)
        Divider()
        Text("LOCAL DATA SECURITY LAB", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        Text("Manual checks for the client-owned app: local files, preferences, databases, logs, backups and privacy exposure. Do not copy secrets into notes.", style = MaterialTheme.typography.bodySmall)
        Text("Check ${localDataCase + 1} of ${localDataChecks.size}", style = MaterialTheme.typography.labelMedium)
        Text(localDataChecks[localDataCase], style = MaterialTheme.typography.bodyMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedButton(onClick = { localDataCase = (localDataCase - 1).coerceAtLeast(0); localDataOutcome = "NOT TESTED"; localDataEvidence = "" }, enabled = localDataCase > 0) { Text("Previous") }
            OutlinedButton(onClick = { localDataCase = (localDataCase + 1).coerceAtMost(localDataChecks.lastIndex); localDataOutcome = "NOT TESTED"; localDataEvidence = "" }, enabled = localDataCase < localDataChecks.lastIndex) { Text("Next") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) { listOf("NOT TESTED", "PASS", "FAIL", "NEEDS REVIEW").forEach { value -> FilterChip(selected = localDataOutcome == value, onClick = { localDataOutcome = value }, label = { Text(value) }) } }
        OutlinedTextField(localDataEvidence, { localDataEvidence = it }, label = { Text("Redacted evidence reference / notes") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        Button(onClick = {
            val arr = runCatching { JSONArray(localDataJson) }.getOrElse { JSONArray() }
            arr.put(JSONObject().put("id", "LD-${System.currentTimeMillis()}").put("testCase", localDataChecks[localDataCase]).put("operatorOutcome", localDataOutcome).put("evidenceReference", localDataEvidence.trim()).put("recordedAt", DateFormat.getDateTimeInstance().format(Date())).put("status", "OPERATOR RECORDED • NOT INDEPENDENTLY VERIFIED"))
            val bounded = JSONArray()
            for (index in (arr.length() - 100).coerceAtLeast(0) until arr.length()) bounded.put(arr.getJSONObject(index))
            localDataJson = bounded.toString()
            prefs.edit().putString("local_data_records", localDataJson).apply()
            localDataEvidence = ""
            status = "LOCAL DATA SECURITY LAB observation saved locally."
        }, enabled = authorized && localDataOutcome != "NOT TESTED", modifier = Modifier.fillMaxWidth()) { Text("Save local data security lab result") }
        val localDataRecords = runCatching { JSONArray(localDataJson) }.getOrElse { JSONArray() }
        val localDataPassCount = (0 until localDataRecords.length()).count { localDataRecords.optJSONObject(it)?.optString("operatorOutcome") == "PASS" }
        val localDataFailCount = (0 until localDataRecords.length()).count { localDataRecords.optJSONObject(it)?.optString("operatorOutcome") == "FAIL" }
        val localDataReviewCount = (0 until localDataRecords.length()).count { localDataRecords.optJSONObject(it)?.optString("operatorOutcome") == "NEEDS REVIEW" }
        Text("Saved: ${localDataRecords.length()} • $localDataPassCount PASS • $localDataFailCount FAIL • $localDataReviewCount NEEDS REVIEW", style = MaterialTheme.typography.labelSmall)
        Divider()
        Text("NETWORK SECURITY REVIEW", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        Text("Manual review of approved app/API traffic and configuration. No traffic interception, certificate bypass or automatic fuzzing is performed.", style = MaterialTheme.typography.bodySmall)
        Text("Check ${networkCase + 1} of ${networkChecks.size}", style = MaterialTheme.typography.labelMedium)
        Text(networkChecks[networkCase], style = MaterialTheme.typography.bodyMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedButton(onClick = { networkCase = (networkCase - 1).coerceAtLeast(0); networkOutcome = "NOT TESTED"; networkEvidence = "" }, enabled = networkCase > 0) { Text("Previous") }
            OutlinedButton(onClick = { networkCase = (networkCase + 1).coerceAtMost(networkChecks.lastIndex); networkOutcome = "NOT TESTED"; networkEvidence = "" }, enabled = networkCase < networkChecks.lastIndex) { Text("Next") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) { listOf("NOT TESTED", "PASS", "FAIL", "NEEDS REVIEW").forEach { value -> FilterChip(selected = networkOutcome == value, onClick = { networkOutcome = value }, label = { Text(value) }) } }
        OutlinedTextField(networkEvidence, { networkEvidence = it }, label = { Text("Redacted evidence reference / notes") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        Button(onClick = {
            val arr = runCatching { JSONArray(networkJson) }.getOrElse { JSONArray() }
            arr.put(JSONObject().put("id", "NET-${System.currentTimeMillis()}").put("testCase", networkChecks[networkCase]).put("operatorOutcome", networkOutcome).put("evidenceReference", networkEvidence.trim()).put("recordedAt", DateFormat.getDateTimeInstance().format(Date())).put("status", "OPERATOR RECORDED • NOT INDEPENDENTLY VERIFIED"))
            val bounded = JSONArray()
            for (index in (arr.length() - 100).coerceAtLeast(0) until arr.length()) bounded.put(arr.getJSONObject(index))
            networkJson = bounded.toString()
            prefs.edit().putString("network_security_records", networkJson).apply()
            networkEvidence = ""
            status = "NETWORK SECURITY REVIEW observation saved locally."
        }, enabled = authorized && networkOutcome != "NOT TESTED", modifier = Modifier.fillMaxWidth()) { Text("Save network security review result") }
        val networkRecords = runCatching { JSONArray(networkJson) }.getOrElse { JSONArray() }
        val networkPassCount = (0 until networkRecords.length()).count { networkRecords.optJSONObject(it)?.optString("operatorOutcome") == "PASS" }
        val networkFailCount = (0 until networkRecords.length()).count { networkRecords.optJSONObject(it)?.optString("operatorOutcome") == "FAIL" }
        val networkReviewCount = (0 until networkRecords.length()).count { networkRecords.optJSONObject(it)?.optString("operatorOutcome") == "NEEDS REVIEW" }
        Text("Saved: ${networkRecords.length()} • $networkPassCount PASS • $networkFailCount FAIL • $networkReviewCount NEEDS REVIEW", style = MaterialTheme.typography.labelSmall)
        Divider()
        Text("PURCHASE & SUBSCRIPTION SECURITY LAB", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        Text("Use official billing sandbox and client-owned test accounts. These checks assess server entitlement correctness; they do not alter real purchases or bypass payment.", style = MaterialTheme.typography.bodySmall)
        Text("Billing check ${billingCase + 1} of ${billingLifecycleChecks.size}", style = MaterialTheme.typography.labelMedium)
        Text(billingLifecycleChecks[billingCase], style = MaterialTheme.typography.bodyMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedButton(onClick = { billingCase = (billingCase - 1).coerceAtLeast(0); billingOutcome = "NOT TESTED"; billingEvidence = "" }, enabled = billingCase > 0) { Text("Previous") }
            OutlinedButton(onClick = { billingCase = (billingCase + 1).coerceAtMost(billingLifecycleChecks.lastIndex); billingOutcome = "NOT TESTED"; billingEvidence = "" }, enabled = billingCase < billingLifecycleChecks.lastIndex) { Text("Next") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) { listOf("NOT TESTED", "PASS", "FAIL", "NEEDS REVIEW").forEach { value -> FilterChip(selected = billingOutcome == value, onClick = { billingOutcome = value }, label = { Text(value) }) } }
        OutlinedTextField(billingEvidence, { billingEvidence = it }, label = { Text("Redacted sandbox evidence reference / notes") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        Button(onClick = {
            val arr = runCatching { JSONArray(billingJson) }.getOrElse { JSONArray() }
            arr.put(JSONObject().put("id", "BILL-${System.currentTimeMillis()}").put("testCase", billingLifecycleChecks[billingCase]).put("operatorOutcome", billingOutcome).put("evidenceReference", billingEvidence.trim()).put("recordedAt", DateFormat.getDateTimeInstance().format(Date())).put("status", "OPERATOR RECORDED • NOT INDEPENDENTLY VERIFIED"))
            val bounded = JSONArray()
            for (index in (arr.length() - 100).coerceAtLeast(0) until arr.length()) bounded.put(arr.getJSONObject(index))
            billingJson = bounded.toString()
            prefs.edit().putString("billing_lifecycle_records", billingJson).apply()
            billingEvidence = ""
            status = "Billing lifecycle observation saved locally."
        }, enabled = authorized && billingOutcome != "NOT TESTED", modifier = Modifier.fillMaxWidth()) { Text("Save billing lifecycle result") }
        val billingRecords = runCatching { JSONArray(billingJson) }.getOrElse { JSONArray() }
        val billingPass = (0 until billingRecords.length()).count { billingRecords.optJSONObject(it)?.optString("operatorOutcome") == "PASS" }
        val billingFail = (0 until billingRecords.length()).count { billingRecords.optJSONObject(it)?.optString("operatorOutcome") == "FAIL" }
        val billingReview = (0 until billingRecords.length()).count { billingRecords.optJSONObject(it)?.optString("operatorOutcome") == "NEEDS REVIEW" }
        Text("Saved: ${billingRecords.length()} • $billingPass PASS • $billingFail FAIL • $billingReview NEEDS REVIEW", style = MaterialTheme.typography.labelSmall)
        Text("STRUCTURED VULNERABILITY FINDINGS", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        Text("Record only findings you have reproduced or have evidence to support. A suspected issue must be labelled as unconfirmed in its title or notes.", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(findingTitle, { findingTitle = it }, label = { Text("Finding title") }, modifier = Modifier.fillMaxWidth())
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            listOf("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL").forEach { level ->
                FilterChip(selected = findingSeverity == level, onClick = { findingSeverity = level }, label = { Text(level) })
            }
        }
        OutlinedTextField(findingCvss, { findingCvss = it }, label = { Text("CVSS v3.1 base score (optional, 0.0–10.0)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(findingCwe, { findingCwe = it }, label = { Text("CWE reference (optional, e.g. CWE-862)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(findingSteps, { findingSteps = it }, label = { Text("Reproduction steps / preconditions") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        OutlinedTextField(findingImpact, { findingImpact = it }, label = { Text("Observed impact and evidence reference") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        OutlinedTextField(findingFix, { findingFix = it }, label = { Text("Recommended remediation") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        Button(onClick = {
            val arr = runCatching { JSONArray(findingsJson) }.getOrElse { JSONArray() }
            arr.put(JSONObject().put("id", "F-${System.currentTimeMillis()}").put("title", findingTitle.trim()).put("severity", findingSeverity).put("cvssBaseScore", findingCvss.toFloatOrNull()?.takeIf { it in 0f..10f } ?: JSONObject.NULL).put("cweReference", findingCwe.trim()).put("reproduction", findingSteps).put("impactEvidence", findingImpact).put("remediation", findingFix).put("status", "UNVERIFIED • NEEDS REVIEW").put("createdAt", DateFormat.getDateTimeInstance().format(Date())))
            findingsJson = arr.toString()
            prefs.edit().putString("findings_json", findingsJson).apply()
            findingTitle = ""; findingCvss = ""; findingCwe = ""; findingSteps = ""; findingImpact = ""; findingFix = ""
            status = "Finding record saved locally. Severity is operator-assigned, not automatically validated."
        }, enabled = authorized && findingTitle.isNotBlank() && findingSteps.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Save evidence-backed finding") }
        val savedFindings = runCatching { JSONArray(findingsJson) }.getOrElse { JSONArray() }
        Text("Saved findings: ${savedFindings.length()}", style = MaterialTheme.typography.bodyMedium)
        val findingStatusOptions = listOf("OPEN", "IN PROGRESS", "READY TO RETEST", "RETEST RECORDED • REVIEW", "CLOSED")
        val findingStatusCounts = findingStatusOptions.associateWith { wanted -> (0 until savedFindings.length()).count { savedFindings.optJSONObject(it)?.optString("workflowStatus", "OPEN") == wanted } }
        Text(findingStatusOptions.joinToString("  •  ") { "${it}: ${findingStatusCounts[it] ?: 0}" }, style = MaterialTheme.typography.labelSmall)
        for (findingIndex in 0 until savedFindings.length()) {
            val findingItem = savedFindings.optJSONObject(findingIndex) ?: continue
            val currentFindingStatus = findingItem.optString("workflowStatus", "OPEN")
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text("${findingItem.optString("severity")} • ${findingItem.optString("title")}", style = MaterialTheme.typography.bodyMedium)
                    Text("CVSS: ${findingItem.opt("cvssBaseScore")?.toString() ?: "Not supplied"} • CWE: ${findingItem.optString("cweReference", "Not supplied")}", style = MaterialTheme.typography.labelSmall)
                    Text("Workflow: $currentFindingStatus", style = MaterialTheme.typography.labelMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        OutlinedButton(onClick = {
                            val updated = JSONArray(findingsJson)
                            val item = updated.optJSONObject(findingIndex)
                            if (item != null) {
                                val nextStatus = findingStatusOptions[(findingStatusOptions.indexOf(item.optString("workflowStatus", "OPEN")) + 1).mod(findingStatusOptions.size)]
                                item.put("workflowStatus", nextStatus).put("workflowUpdatedAt", DateFormat.getDateTimeInstance().format(Date()))
                                findingsJson = updated.toString()
                                prefs.edit().putString("findings_json", findingsJson).apply()
                                status = "Finding workflow updated: $nextStatus"
                            }
                        }, enabled = authorized) { Text("Advance status") }
                        TextButton(onClick = {
                            val updated = JSONArray(findingsJson)
                            val item = updated.optJSONObject(findingIndex)
                            if (item != null) { item.put("workflowStatus", "OPEN").put("workflowUpdatedAt", DateFormat.getDateTimeInstance().format(Date())); findingsJson = updated.toString(); prefs.edit().putString("findings_json", findingsJson).apply(); status = "Finding reopened for review." }
                        }, enabled = authorized) { Text("Reopen") }
                    }
                }
            }
        }
        if (savedFindings.length() > 0) {
            val latest = savedFindings.optJSONObject(savedFindings.length() - 1)
            if (latest != null) Text("Latest: ${latest.optString("severity")} • ${latest.optString("title")} • ${latest.optString("status")}", style = MaterialTheme.typography.bodySmall)
        }
        OutlinedTextField(notes, { notes = it; prefs.edit().putString("notes", it).apply() }, label = { Text("Evidence notes / findings references") }, modifier = Modifier.fillMaxWidth(), minLines = 3)
        Button(onClick = { export.launch("omni-blackbox-${packageName}.json") }, enabled = authorized && target.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Export scoped test plan & evidence index") }
        OutlinedButton(onClick = { pdfExport.launch("omni-client-security-report-${packageName}.pdf") }, enabled = authorized && target.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Export professional client PDF report") }
        Text(if (authorized) status else "Export is disabled until the operator confirms client authorization.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
        Text("No exploit is launched automatically. The checklist records manual assessment coverage; checked items are not vulnerability proof or remediation confirmation.", style = MaterialTheme.typography.labelSmall)
    }
}