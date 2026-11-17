package com.omni.cyberlab

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
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

data class AppRow(val label:String,val pkg:String,val version:String,val permissions:List<String>,
 val exported:Int,val debuggable:Boolean,val signer:String)

class MainActivity:ComponentActivity(){
 private fun installedApps():List<AppRow>{
  val pm=packageManager
  return pm.getInstalledPackages(PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or
   PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or
   PackageManager.GET_SIGNING_CERTIFICATES).mapNotNull{p->try{
    val ai=p.applicationInfo?:return@mapNotNull null
    val exported=(p.activities?.count{it.exported}?:0)+(p.services?.count{it.exported}?:0)+
     (p.receivers?.count{it.exported}?:0)+(p.providers?.count{it.exported}?:0)
    val cert=p.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
    val fp=cert?.let{MessageDigest.getInstance("SHA-256").digest(it).joinToString(":"){b->"%02X".format(b)}}?:"Unavailable"
    AppRow(pm.getApplicationLabel(ai).toString(),p.packageName,p.versionName?:"Unknown",
     p.requestedPermissions?.toList()?:emptyList(),exported,
     (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE)!=0,fp)
   }catch(_:Exception){null}}.sortedBy{it.label.lowercase()}
 }
 private fun safeDiagnostic(cmd:String):String{
  val allowed=setOf("pm list packages -3","getprop ro.build.version.release","getprop ro.build.version.sdk","id")
  require(cmd in allowed){"Command not allowlisted"}
  val p=Shizuku.newProcess(arrayOf("sh","-c",cmd),null,null)
  val out=p.inputStream.bufferedReader().readText()
  val err=p.errorStream.bufferedReader().readText()
  val code=p.waitFor()
  return ("$cmd\nExit: $code\n$out\n$err").take(10000)
 }
 override fun onCreate(savedInstanceState:Bundle?){super.onCreate(savedInstanceState)
  setContent{MaterialTheme{
   var apps by remember{mutableStateOf(emptyList<AppRow>())}
   var selected by remember{mutableStateOf<AppRow?>(null)}
   var query by remember{mutableStateOf("")}
   var busy by remember{mutableStateOf(false)}
   var bridge by remember{mutableStateOf("Checking Shizuku…")}
   var output by remember{mutableStateOf("No diagnostic run yet.")}
   val scope= rememberCoroutineScope()
   fun refresh(){bridge=try{when{
    !Shizuku.pingBinder()->"Shizuku service is not running"
    Shizuku.checkSelfPermission()==PackageManager.PERMISSION_GRANTED->"Connected • permission granted"
    else->"Service connected • permission required"
   }}catch(e:Exception){"Unavailable: ${e.message}"}}
   fun scan(){scope.launch{busy=true;apps=withContext(Dispatchers.IO){installedApps()};busy=false}}
   fun diag(cmd:String){scope.launch{busy=true;output=try{withContext(Dispatchers.IO){safeDiagnostic(cmd)}}catch(e:Exception){"Failed: ${e.message}. Check Shizuku service and permission."};busy=false}}
   LaunchedEffect(Unit){scan();refresh()}
   Column(Modifier.fillMaxSize().padding(16.dp)){
    Text("OMNI CYBER LAB",style=MaterialTheme.typography.headlineSmall)
    Text("Offline-first Android security inventory")
    Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){
     Button(onClick={scan()},enabled=!busy){Text(if(busy)"Working…" else "Auto Scan")}
     OutlinedButton(onClick={selected=null}){Text("All apps")}
    }
    Card(Modifier.fillMaxWidth().padding(vertical=8.dp)){Column(Modifier.padding(12.dp)){
     Text("Shizuku / ADB bridge",style=MaterialTheme.typography.titleMedium);Text(bridge)
     Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){
      Button(onClick={try{if(!Shizuku.pingBinder())bridge="Start Shizuku first"
       else if(Shizuku.checkSelfPermission()!=PackageManager.PERMISSION_GRANTED){Shizuku.requestPermission(4102);bridge="Permission request sent"}
       else refresh()}catch(e:Exception){bridge="Error: ${e.message}"}}){Text("Grant / Check")}
      OutlinedButton(onClick={refresh}){Text("Refresh")}
     }
     Text("Allowlisted read-only diagnostics")
     Row(horizontalArrangement=Arrangement.spacedBy(4.dp)){
      OutlinedButton(enabled=!busy,onClick={diag("pm list packages -3")}){Text("Third-party apps")}
      OutlinedButton(enabled=!busy,onClick={diag("getprop ro.build.version.release")}){Text("Android version")}
     }
     Row(horizontalArrangement=Arrangement.spacedBy(4.dp)){
      OutlinedButton(enabled=!busy,onClick={diag("getprop ro.build.version.sdk")}){Text("SDK level")}
      OutlinedButton(enabled=!busy,onClick={diag("id")}){Text("Shell identity")}
     }
     Text(output,style=MaterialTheme.typography.bodySmall)
    }}
    OutlinedTextField(query,{query=it},label={Text("Search installed apps")},modifier=Modifier.fillMaxWidth())
    Text("${apps.size} visible packages")
    selected?.let{a->Card(Modifier.fillMaxWidth().padding(vertical=8.dp)){Column(Modifier.padding(12.dp)){
     Text(a.label,style=MaterialTheme.typography.titleLarge);Text(a.pkg);Text("Version: ${a.version}")
     Text("Exported components: ${a.exported}");Text("Debuggable: ${a.debuggable}");Text("Signer SHA-256: ${a.signer}")
     Text("Requested permissions (${a.permissions.size})")
     a.permissions.forEach{Text("• $it",style=MaterialTheme.typography.bodySmall)}
     if(a.debuggable)Text("HIGH: debuggable build flag detected")
     if(a.exported>0)Text("REVIEW: inspect exported component access controls")
     if(a.permissions.any{it.contains("SMS")||it.contains("CONTACTS")||it.contains("RECORD_AUDIO")||it.contains("LOCATION")})Text("REVIEW: sensitive permission requested")
    }}}
    LazyColumn(Modifier.weight(1f)){items(apps.filter{it.label.contains(query,true)||it.pkg.contains(query,true)}){a->
     ListItem(headlineContent={Text(a.label)},supportingContent={Text("${a.pkg} • ${a.version}")},
      trailingContent={TextButton(onClick={selected=a}){Text("Inspect")}})
     HorizontalDivider()
    }}
    Text("Metadata audit only; private app data remains protected by Android sandboxing.",style=MaterialTheme.typography.bodySmall)
   }
  }}
 }
}
