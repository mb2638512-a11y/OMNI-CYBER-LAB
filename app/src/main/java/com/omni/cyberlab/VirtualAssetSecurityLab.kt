package com.omni.cyberlab

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

private data class VirtualAssetCase(val id: String, val area: String, val title: String, val attackerAction: String, val secureExpected: String, val evidenceHint: String)

private val virtualAssetCases = listOf(
    VirtualAssetCase("premium_flag", "VIP / PRO", "Local premium flag tampering", "In an owner test build, change the local premium boolean or preference and reopen a premium screen.", "UI may be visually influenced, but protected backend data/actions must still deny access without a valid entitlement.", "Record whether protected API/content access was denied; attach app/backend logs."),
    VirtualAssetCase("subscription_expiry", "VIP / PRO", "Expired subscription replay", "Use a test account whose subscription has expired, then relaunch and restore purchases.", "Expired entitlement is not restored; server state and client UI converge on the expired state.", "Record subscription state, expiry timestamp and server response."),
    VirtualAssetCase("subscription_refund", "VIP / PRO", "Refund / revoke propagation", "Refund or revoke a test purchase through Play Console test workflows, then refresh entitlement.", "Entitlement is revoked within the app policy window and protected endpoints deny access.", "Record revocation event, reconciliation time and access result."),
    VirtualAssetCase("pending_purchase", "PURCHASES", "Pending purchase must not unlock", "Use a Play license-tester pending payment scenario.", "No VIP, coins or goods are granted until purchase state becomes PURCHASED and verification succeeds.", "Record purchase state before and after completion."),
    VirtualAssetCase("fake_receipt", "PURCHASES", "Forged receipt / signature rejection", "In a controlled test harness, submit a deliberately invalid receipt fixture to your own verification endpoint.", "Backend rejects invalid signature/token and creates no entitlement or inventory credit.", "Record HTTP status, backend decision code and inventory delta."),
    VirtualAssetCase("token_replay", "PURCHASES", "Purchase-token replay / duplicate delivery", "Submit the same test purchase token twice to your own backend using the approved test harness.", "Second delivery is idempotent; no duplicate entitlement or consumable credit is granted.", "Record token fingerprint, idempotency key and balance delta."),
    VirtualAssetCase("wrong_sku", "PURCHASES", "Wrong product / package binding", "Use a valid test token mapped to a different package or product in your own backend test fixture.", "Backend rejects package, product or offer mismatch.", "Record expected and received product identifiers without exposing tokens."),
    VirtualAssetCase("account_swap", "IDENTITY", "Account switching / entitlement transfer", "Purchase under test account A, then sign in as account B on the same device.", "Entitlement remains bound to the correct account; B cannot inherit A’s purchase.", "Record anonymized account IDs and entitlement lookup results."),
    VirtualAssetCase("offline_unlock", "CLIENT TRUST", "Offline entitlement manipulation", "In a test build, alter cached entitlement state while offline, then request protected content after reconnect.", "Offline cache follows an explicit grace policy; backend denies unauthorized protected operations after reconnect.", "Record offline UI behavior and first authenticated server decision."),
    VirtualAssetCase("coin_balance", "COINS / GOLD", "Local coin / gold balance tampering", "In an owner test build, alter the displayed local balance or local database fixture.", "Server-side wallet balance remains authoritative; spending is rejected if server balance is insufficient.", "Record before/after server balance and transaction ledger ID."),
    VirtualAssetCase("negative_balance", "COINS / GOLD", "Negative / overflow / precision edge cases", "Send boundary values from a controlled test client: negative, zero, maximum integer and excessive decimal amounts.", "Backend validates type, range, precision and business rules; no overflow or unintended credit occurs.", "Record rejected values, validation code and ledger delta."),
    VirtualAssetCase("reward_replay", "REWARDS", "Reward callback replay", "Replay a completed test reward callback/event ID against your own test backend.", "Each reward event is credited at most once using a unique event/idempotency key.", "Record event fingerprint and wallet ledger entries."),
    VirtualAssetCase("double_spend", "COINS / GOLD", "Concurrent double-spend race", "Use two owner-controlled test sessions to spend the same limited balance at nearly the same time.", "Atomic server transaction allows only valid spend(s); balance never goes below policy limits.", "Record both request IDs, transaction ordering and final balance."),
    VirtualAssetCase("price_tamper", "PURCHASES", "Client price / quantity tampering", "Change client-submitted price or quantity in a local mock request to your own test endpoint.", "Backend derives price and allowed quantity from trusted product configuration, not client-supplied totals.", "Record configured price, submitted value and server decision."),
    VirtualAssetCase("ad_reward", "ADS / REWARDS", "Rewarded-ad completion spoof", "In an owner test build, call the local mock completion callback without a verified ad reward event.", "No reward is granted unless the expected SDK/server-side verification or trusted test event succeeds.", "Record callback source, verification result and wallet delta."),
    VirtualAssetCase("rate_limit", "ABUSE CONTROLS", "Rapid purchase / reward request abuse", "Generate bounded repeated requests against a staging endpoint you own, within the engagement rate limit.", "Rate limits, abuse controls and idempotency prevent duplicate credits and protect service availability.", "Record request count, throttling response and any balance change."),
    VirtualAssetCase("leaderboard", "GAME INTEGRITY", "Client score / inventory authority", "Submit an obviously invalid score or item ownership claim from your controlled test client.", "Server validates game-critical state and rejects impossible scores or unowned item actions.", "Record validation reason and whether leaderboard/inventory changed."),
    VirtualAssetCase("restore", "PURCHASES", "Restore purchase reconciliation", "Restore purchases after reinstall or on a second owner-controlled test device.", "Backend maps verified purchases to the correct account and does not duplicate consumable credits.", "Record restored product IDs, account mapping and ledger delta.")
)

@Composable
fun VirtualAssetSecurityLab(context: Context, packageName: String, modifier: Modifier = Modifier) {
    val prefs = remember(context, packageName) { context.getSharedPreferences("omni_virtual_asset_lab_$packageName", Context.MODE_PRIVATE) }
    val scope = rememberCoroutineScope()
    var authorized by remember(packageName) { mutableStateOf(prefs.getBoolean("authorized", false)) }
    var selectedArea by remember(packageName) { mutableStateOf("ALL") }
    var expandedId by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("Choose an authorized test engagement and record observed outcomes. Nothing is sent to the target automatically.") }
    val areas = listOf("ALL", "VIP / PRO", "PURCHASES", "COINS / GOLD", "REWARDS", "ADS / REWARDS", "IDENTITY", "CLIENT TRUST", "ABUSE CONTROLS", "GAME INTEGRITY")
    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri: Uri? ->
        if (uri != null) scope.launch {
            try {
                val payload = JSONObject().put("packageName", packageName).put("generatedAt", java.text.DateFormat.getDateTimeInstance().format(java.util.Date()))
                    .put("authorizationConfirmedByOperator", authorized)
                    .put("notice", "Operator-recorded test outcomes; not independently verified by OMNI CYBER LAB.")
                    .put("cases", JSONArray().apply { virtualAssetCases.forEach { c -> put(JSONObject().put("id", c.id).put("area", c.area).put("title", c.title).put("attackerAction", c.attackerAction).put("secureExpected", c.secureExpected).put("status", prefs.getString("result_${c.id}", "NOT RUN")).put("evidence", prefs.getString("evidence_${c.id}", "") ?: "")) } })
                withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(payload.toString(2)) } ?: error("Could not open export destination.") }
                status = "Virtual asset test report exported as JSON."
            } catch (e: Exception) { status = "Export failed: ${e.message ?: "unknown error"}" }
        }
    }
    val filtered = virtualAssetCases.filter { selectedArea == "ALL" || it.area == selectedArea }
    val passCount = virtualAssetCases.count { prefs.getString("result_${it.id}", "NOT RUN") == "PASS" }
    val failCount = virtualAssetCases.count { prefs.getString("result_${it.id}", "NOT RUN") == "FAIL" }
    val attemptedCount = virtualAssetCases.count { prefs.getString("result_${it.id}", "NOT RUN") != "NOT RUN" }
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(9.dp)) {
        Text("VIP • COINS • GOLD • GAME ASSET SECURITY LAB", color = Color(0xFF55E6A5), fontWeight = FontWeight.ExtraBold, fontSize = 12.sp)
        Text("Owner-authorized attacker simulation + defender validation. Scenarios use your own staging build, test accounts and backend; OMNI does not unlock third-party paid content or alter live balances.", color = Color(0xFFFFB454), fontSize = 10.sp)
        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF18232D))) {
            Column(Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("ENGAGEMENT AUTHORIZATION", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Checkbox(checked = authorized, onCheckedChange = { authorized = it; prefs.edit().putBoolean("authorized", it).apply() })
                    Text("I own this app or have explicit client permission for the selected tests.", color = Color(0xFFB8C5D6), fontSize = 10.sp)
                }
                Text("Package: $packageName", color = Color(0xFF91A2B8), fontSize = 9.sp)
                Text("Progress: $attemptedCount/${virtualAssetCases.size} attempted • $passCount PASS • $failCount FAIL", color = Color(0xFF55E6A5), fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }
        }
        Text("TEST CATEGORY", color = Color(0xFF55E6A5), fontWeight = FontWeight.Bold, fontSize = 10.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            areas.take(5).forEach { area -> FilterChip(selected = selectedArea == area, onClick = { selectedArea = area }, label = { Text(area, fontSize = 9.sp) }) }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            areas.drop(5).forEach { area -> FilterChip(selected = selectedArea == area, onClick = { selectedArea = area }, label = { Text(area, fontSize = 9.sp) }) }
        }
        filtered.forEach { c ->
            val result = prefs.getString("result_${c.id}", "NOT RUN") ?: "NOT RUN"
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF18232D))) {
                Column(Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(c.area, color = Color(0xFF55E6A5), fontSize = 8.sp, fontWeight = FontWeight.Bold)
                            Text(c.title, color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                        Text(result, color = when (result) { "PASS" -> Color(0xFF55E6A5); "FAIL" -> Color(0xFFFF6878); "BLOCKED" -> Color(0xFFFFB454); else -> Color(0xFF91A2B8) }, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                    }
                    Text("ATTACK SIMULATION: ${c.attackerAction}", color = Color(0xFFB8C5D6), fontSize = 9.sp)
                    Text("DEFENDER EXPECTATION: ${c.secureExpected}", color = Color(0xFF91A2B8), fontSize = 9.sp)
                    TextButton(onClick = { expandedId = if (expandedId == c.id) "" else c.id }) { Text(if (expandedId == c.id) "Hide test record" else "Record test outcome / evidence") }
                    if (expandedId == c.id) {
                        var evidence by remember(c.id) { mutableStateOf(prefs.getString("evidence_${c.id}", "") ?: "") }
                        var chosen by remember(c.id) { mutableStateOf(result) }
                        Text("Observed outcome (operator recorded)", color = Color(0xFF91A2B8), fontSize = 9.sp)
                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            listOf("NOT RUN", "PASS", "FAIL", "BLOCKED").forEach { option ->
                                FilterChip(selected = chosen == option, onClick = { chosen = option }, label = { Text(option, fontSize = 8.sp) })
                            }
                        }
                        OutlinedTextField(value = evidence, onValueChange = { evidence = it.take(1200) }, modifier = Modifier.fillMaxWidth(), label = { Text(c.evidenceHint) }, minLines = 2)
                        Button(onClick = {
                            if (!authorized && chosen != "NOT RUN") status = "Confirm ownership / written authorization before recording an active test."
                            else { prefs.edit().putString("result_${c.id}", chosen).putString("evidence_${c.id}", evidence).apply(); status = "Saved ${c.title}: $chosen" }
                        }, modifier = Modifier.fillMaxWidth()) { Text("Save test record") }
                    }
                }
            }
        }
        OutlinedButton(onClick = { exportLauncher.launch("omni-virtual-asset-audit-${packageName.substringAfterLast(".")}.json") }, modifier = Modifier.fillMaxWidth()) { Text("Export VIP / coins / game-assets report") }
        Text("STATUS: $status", color = Color(0xFF91A2B8), fontSize = 9.sp)
        Text("IMPORTANT: PASS / FAIL is an operator-entered observation, not an automatic security verdict. Do not test production users or real payment methods; use Play license testers and staging wallets.", color = Color(0xFFFFB454), fontSize = 9.sp)
    }
}
