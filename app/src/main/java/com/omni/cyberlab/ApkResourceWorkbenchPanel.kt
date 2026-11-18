package com.omni.cyberlab

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun ApkResourceWorkbenchPanel(context: Context, modifier: Modifier = Modifier) {
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF18232D))) {
            Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                Text("FULL APK ENGINEERING • WINDOWS + ON-DEVICE ARM64", color = Color(0xFF55E6A5), fontSize = 11.sp, fontWeight = FontWeight.ExtraBold)
                Text("Decode binary AndroidManifest.xml, resources.arsc and DEX into Smali; edit supported resources and Smali, then rebuild an unsigned APK with Apktool.", color = Color(0xFFB8C5D6), fontSize = 10.sp)
                Text("Evidence reports: source/output SHA-256, archive integrity, manifest and resource-table presence, resource inventory, APK entry counts and signature verification status. Runtime/install checks remain NOT TESTED until actually performed.", color = Color(0xFF91A2B8), fontSize = 10.sp)
                Text("Workflow: 1) Decode your authorized APK. 2) Edit res/, assets/ or Smali source. 3) Rebuild resources, manifest and DEX. 4) Review reports. 5) Sign with your own keystore. 6) Verify and test on a controlled device.", color = Color(0xFF91A2B8), fontSize = 9.sp)
                Text("On-device full APK rebuilding is available through the Termux ARM64 companion script. It uses native AAPT2 and Apktool to rebuild Smali into DEX alongside resources and manifest, then zipaligns the unsigned output. Re-signing changes update compatibility. Use only owned or explicitly authorized APKs.", color = Color(0xFFFFB454), fontSize = 9.sp)
                Button(onClick = {
                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/mb2638512-a11y/OMNI-CYBER-LAB/blob/main/tools/apktool-workbench/omni-apktool-android.sh"))
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(intent)
                }, modifier = Modifier.fillMaxWidth()) { Text("Open on-device ARM64 rebuild script") }
                Button(onClick = {
                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/mb2638512-a11y/OMNI-CYBER-LAB/tree/main/tools/apktool-workbench"))
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(intent)
                }, modifier = Modifier.fillMaxWidth()) { Text("Open resource decode / rebuild guide") }
            }
        }
    }
}
