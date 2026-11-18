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
                Text("FULL APK RESOURCE WORKBENCH • WINDOWS PC", color = Color(0xFF55E6A5), fontSize = 11.sp, fontWeight = FontWeight.ExtraBold)
                Text("For complete binary resource decoding and rebuilding, use the companion Windows helper included in the GitHub repository. It verifies the official Apktool JAR hash, decodes AndroidManifest.xml and res/ resources, lets you edit the decoded project, then rebuilds an unsigned APK.", color = Color(0xFFB8C5D6), fontSize = 10.sp)
                Text("1. Export your own / authorized APK from this device.  2. On Windows, install Java 17+.  3. Run the helper's Decode command.  4. Edit permitted resources.  5. Run Build.  6. Re-import the unsigned APK here and sign with your own keystore.", color = Color(0xFF91A2B8), fontSize = 9.sp)
                Text("Resource rebuild is a desktop companion workflow, not an on-device rebuild yet. Re-signing changes app identity. Do not alter third-party payment, license or entitlement logic.", color = Color(0xFFFFB454), fontSize = 9.sp)
                Button(onClick = {
                    val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/mb2638512-a11y/OMNI-CYBER-LAB/tree/main/tools/apktool-workbench"))
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(intent)
                }, modifier = Modifier.fillMaxWidth()) { Text("Open Windows resource workbench") }
            }
        }
    }
}
