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
import androidx.compose.ui.unit.dp
import org.json.JSONArray
import org.json.JSONObject
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.net.URI
import java.util.Date

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
    val prefs = remember(context, packageName) { context.getSharedPreferences("omni_blackbox_$packageName", Context.MODE_PRIVATE) }
    val scope = rememberCoroutineScope()
    var target by remember(packageName) { mutableStateOf(prefs.getString("target", packageName) ?: packageName) }
    var apiHosts by remember(packageName) { mutableStateOf(prefs.getString("hosts", "") ?: "") }
    var exclusions by remember(packageName) { mutableStateOf(prefs.getString("exclusions", "") ?: "") }
    var testWindow by remember(packageName) { mutableStateOf(prefs.getString("window", "Client-agreed schedule") ?: "Client-agreed schedule") }
    var authorized by remember(packageName) { mutableStateOf(prefs.getBoolean("authorized", false)) }
    var notes by remember(packageName) { mutableStateOf(prefs.getString("notes", "") ?: "") }
    var checked by remember(packageName) { mutableStateOf(blackBoxChecks.indices.filter { prefs.getBoolean("check_$it", false) }.toSet()) }
    var status by remember { mutableStateOf("Define the client scope before starting an engagement.") }
    var endpoint by remember(packageName) { mutableStateOf(prefs.getString("probe_endpoint", "") ?: "") }
    var probeMethod by remember(packageName) { mutableStateOf(prefs.getString("probe_method", "GET") ?: "GET") }
    var probeBusy by remember { mutableStateOf(false) }
    var probeResult by remember(packageName) { mutableStateOf(prefs.getString("probe_result", "") ?: "") }
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
                .put("limitations", "This is a scoped manual test record, not proof of exploitability or a passed security assessment.")
            scope.launch {
                try { context.contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(payload.toString(2)) } ?: error("Cannot open export destination."); status = "Engagement plan exported." }
                catch (e: Exception) { status = "Export failed: ${e.message}" }
            }
        }
    }
    Column(modifier.fillMaxWidth().padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
        Text("BLIND / BLACK-BOX PENETRATION TEST", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.titleSmall)
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
                    prefs.edit().putString("probe_result", probeResult).apply()
                    status = "Scoped endpoint probe complete: HTTP ${result.statusCode} in ${result.durationMs} ms."
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
                Text("Security headers: ${p.optJSONObject("securityHeaders")?.length() ?: 0} observed • Body bytes hashed: ${p.optInt("bodyBytesRead")}", style = MaterialTheme.typography.bodySmall)
            }
        }
        Text("This probe validates reachability and records response metadata; it does not prove an endpoint is vulnerable or secure.", style = MaterialTheme.typography.labelSmall)
        OutlinedTextField(notes, { notes = it; prefs.edit().putString("notes", it).apply() }, label = { Text("Evidence notes / findings references") }, modifier = Modifier.fillMaxWidth(), minLines = 3)
        Button(onClick = { export.launch("omni-blackbox-${packageName}.json") }, enabled = authorized && target.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Export scoped test plan & evidence index") }
        Text(if (authorized) status else "Export is disabled until the operator confirms client authorization.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
        Text("No exploit is launched automatically. The checklist records manual assessment coverage; checked items are not vulnerability proof or remediation confirmation.", style = MaterialTheme.typography.labelSmall)
    }
}