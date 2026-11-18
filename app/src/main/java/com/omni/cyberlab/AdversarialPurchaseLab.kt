package com.omni.cyberlab

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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private data class AdversarialCase(val title: String, val detail: String, val expected: String)

private val purchaseAdversarialCases = listOf(
    AdversarialCase("Fake purchase payload", "A client claims PURCHASED without a Google Play token.", "DENY: client state is not proof of payment."),
    AdversarialCase("Pending purchase", "A test purchase remains PENDING.", "DENY entitlement until Google reports PURCHASED."),
    AdversarialCase("Canceled / refunded purchase", "A previously valid purchase is canceled or revoked.", "REVOKE or withhold entitlement after server reconciliation."),
    AdversarialCase("Expired VIP subscription", "Subscription line item expiry is in the past.", "DENY VIP; do not trust cached client flags."),
    AdversarialCase("Wrong product / package", "A valid token is submitted for a different SKU or app.", "DENY on exact package and product mismatch."),
    AdversarialCase("Cross-account token replay", "Same purchase token is submitted by a second account.", "DENY: token remains bound to its original account."),
    AdversarialCase("Duplicate fulfillment", "Same consumable purchase is fulfilled more than once.", "ONE credit only: idempotent server ledger."),
    AdversarialCase("Client-edited coin amount", "Client asks the server to grant an arbitrary amount.", "DENY: amount and currency come from server product config."),
    AdversarialCase("Negative / overflow spend", "Client submits negative, excessive or overflowing spend.", "DENY invalid values; atomic balance must never go below zero."),
    AdversarialCase("Offline entitlement tampering", "Local preferences claim VIP while server cannot verify it.", "Keep protected features locked; use explicit offline grace policy only."),
    AdversarialCase("Ad config regression", "Owned app ad test/staging config is changed or remote config is malformed.", "Use owner-controlled test IDs/config; fail closed and never rewrite third-party apps."),
    AdversarialCase("Ad-free entitlement spoof", "Client toggles an ad-free flag without a verified entitlement.", "Server verifies entitlement; ad suppression follows owned-app policy only.")
)

@Composable
fun AdversarialPurchaseLab(targetPackage: String, modifier: Modifier = Modifier) {
    var results by remember(targetPackage) { mutableStateOf<Map<Int, String>>(emptyMap()) }
    var exploitResults by remember(targetPackage) { mutableStateOf<List<EntitlementSimulationResult>>(emptyList()) }
    var ownerPatchResults by remember(targetPackage) { mutableStateOf<List<EntitlementSimulationResult>>(emptyList()) }
    var selected by remember(targetPackage) { mutableStateOf("ALL") }
    val green = Color(0xFF55E6A5)
    val muted = Color(0xFF9AA6B2)
    val amber = Color(0xFFFFB454)
    val panel = Color(0xFF18232D)
    val visible = purchaseAdversarialCases.withIndex().filter { (_, test) ->
        selected == "ALL" || (selected == "ADS" && test.title.contains("Ad", true)) ||
            (selected == "VIP" && (test.title.contains("purchase", true) || test.title.contains("VIP", true) || test.title.contains("subscription", true))) ||
            (selected == "ECONOMY" && (test.title.contains("coin", true) || test.title.contains("spend", true) || test.title.contains("fulfillment", true)))
    }
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Card(colors = CardDefaults.cardColors(containerColor = panel)) {
            Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("ADVERSARIAL PURCHASE & AD CONFIG LAB", color = green, fontSize = 12.sp, fontWeight = FontWeight.ExtraBold)
                Text("Target: $targetPackage", color = muted, fontSize = 10.sp)
                Text("Offline control-plane simulations only. These buttons do not patch, unlock, spend, or modify the target app. Run live cases only against your own staging backend and Play test track.", color = amber, fontSize = 10.sp)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf("ALL", "ADS", "VIP", "ECONOMY").forEach { filter ->
                        OutlinedButton(onClick = { selected = filter }, modifier = Modifier.weight(1f)) { Text(filter, fontSize = 9.sp) }
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    OutlinedButton(onClick = { results = visible.associate { it.index to "SIMULATED • EXPECTED DENY / CONTROL" } }, modifier = Modifier.weight(1f)) { Text("Run selected simulations", fontSize = 9.sp) }
                    OutlinedButton(onClick = { results = emptyMap() }, modifier = Modifier.weight(1f)) { Text("Reset", fontSize = 9.sp) }
                }
                Text("SIMULATED ${results.size} / ${visible.size} • NOT A LIVE TARGET TEST", color = green, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                OutlinedButton(onClick = { exploitResults = EntitlementAttackSimulator.runSuite() }, modifier = Modifier.fillMaxWidth()) {
                    Text("Run local attacker exploit + hardened-control suite", fontSize = 9.sp)
                }
                OutlinedButton(onClick = { ownerPatchResults = OwnerPatchQaSimulator.runSuite() }, modifier = Modifier.fillMaxWidth()) {
                    Text("Run owner ad-removal + license-resistance QA", fontSize = 9.sp)
                }
                if (ownerPatchResults.isNotEmpty()) {
                    Text("OWNER PATCH QA • ${ownerPatchResults.size} LOCAL TEST CASES • NO APK PATCH APPLIED", color = amber, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                    ownerPatchResults.forEach { result ->
                        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF101B28))) {
                            Column(Modifier.fillMaxWidth().padding(9.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(result.title, color = Color.White, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                Text("TEST: ${result.attackerTechnique}", color = muted, fontSize = 9.sp)
                                Text("WEAK CONTROL: ${result.vulnerableOutcome}", color = Color(0xFFFF6878), fontSize = 9.sp)
                                Text("OWNER CONTROL: ${result.hardenedOutcome}", color = green, fontSize = 9.sp)
                                Text("EVIDENCE: ${result.evidence}", color = muted, fontSize = 8.sp)
                            }
                        }
                    }
                }
                if (exploitResults.isNotEmpty()) {
                    val vulnerableCount = exploitResults.count { it.vulnerable }
                    Text("LOCAL DEMO RESULTS: ${vulnerableCount} vulnerable control(s) detected across ${exploitResults.size} scenarios • no target app contacted", color = amber, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                    exploitResults.forEach { result ->
                        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF101B28))) {
                            Column(Modifier.fillMaxWidth().padding(9.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(result.title, color = Color.White, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                Text("ATTACK: ${result.attackerTechnique}", color = muted, fontSize = 9.sp)
                                Text("VULNERABLE DEMO: ${result.vulnerableOutcome}", color = if (result.vulnerable) Color(0xFFFF6878) else amber, fontSize = 9.sp)
                                Text("HARDENED CONTROL: ${result.hardenedOutcome}", color = green, fontSize = 9.sp)
                                Text("EVIDENCE: ${result.evidence}", color = muted, fontSize = 8.sp)
                            }
                        }
                    }
                    Text("These are deterministic local model results, not findings against ${targetPackage}. Repeat equivalent cases against your own staging app/backend to establish real evidence.", color = amber, fontSize = 9.sp)
                }

                visible.forEach { (index, test) ->
                    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF101B28))) {
                        Column(Modifier.fillMaxWidth().padding(9.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("${index + 1}. ${test.title}", color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            Text(test.detail, color = muted, fontSize = 10.sp)
                            Text("Expected defense: ${test.expected}", color = green, fontSize = 10.sp)
                            Text("STATUS: ${results[index] ?: "NOT RUN"}", color = if (results.containsKey(index)) green else amber, fontSize = 9.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
                Text("Owner-side ad work: configure Google test ad unit IDs, staging remote-config flags, consent gating and an explicit ad-free entitlement in your own app. The APK marker scanner is inventory only; automatic removal from arbitrary installed apps is not provided.", color = amber, fontSize = 10.sp)
                Text("Play verification (backend): Google Android Publisher API verification, exact package/SKU checks, pending/expired/revoked state handling, token hashing and cross-account replay protection. Wallet fulfillment uses server-configured grants and idempotency. RTDN/Pub/Sub push handling validates the OIDC service identity and processes subscription updates; explicit acknowledge and consume endpoints are implemented. Production deployment still requires correct Google service credentials, Pub/Sub audience/service-account configuration and end-to-end Play test-track validation.", color = muted, fontSize = 10.sp)
            }
        }
    }
}