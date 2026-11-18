param(
 [Parameter(Mandatory=$true)][ValidateSet("Decode","Build")][string]$Action,
 [Parameter(Mandatory=$true)][string]$ApkPath,
 [Parameter(Mandatory=$true)][string]$WorkDir,
 [string]$OutputApk="",
 [switch]$ConfirmAuthorized
)
$ErrorActionPreference="Stop"
if(-not $ConfirmAuthorized){throw "Use only APKs you own or have written permission to modify."}
$version="3.0.3"; $jar=Join-Path $PSScriptRoot "apktool_$version.jar"
$expected="dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423"
function Hash([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function Inventory([string]$root){
 $out=@()
 Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
  $rel=$_.FullName.Substring($root.TrimEnd('\').Length+1).Replace('\','/')
  if($rel -match '^(res/|assets/|AndroidManifest\.xml$)'){$out+= [ordered]@{path=$rel;bytes=$_.Length;sha256=(Hash $_.FullName)}}
 }
 return $out
}
function BuildReport([string]$source,[string]$output,[string]$workspace,[object]$meta){
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 $z=[System.IO.Compression.ZipFile]::OpenRead($output)
 try{
  $entries=@($z.Entries|Where-Object{![string]::IsNullOrEmpty($_.Name)})
  $manifest=$entries|Where-Object FullName -eq "AndroidManifest.xml"|Select-Object -First 1
  $table=$entries|Where-Object FullName -eq "resources.arsc"|Select-Object -First 1
  $res=@($entries|Where-Object{$_.FullName.StartsWith("res/")})
  $dex=@($entries|Where-Object{$_.FullName -match '^classes([0-9]*)\.dex$'})
  $native=@($entries|Where-Object{$_.FullName -match '^lib/.+\.so$'})
  if(!$manifest){throw "FAIL: AndroidManifest.xml missing from rebuilt APK."}
  if(!$table){throw "FAIL: resources.arsc missing from rebuilt APK."}
 }finally{$z.Dispose()}
 $before=@{}; foreach($x in @($meta.baselineInventory)){$before[$x.path]=$x.sha256}
 $after=@{}; $now=@(Inventory $workspace); foreach($x in $now){$after[$x.path]=$x.sha256}
 $added=@($now|Where-Object{!$before.ContainsKey($_.path)}|ForEach-Object{$_.path})
 $removed=@($meta.baselineInventory|Where-Object{!$after.ContainsKey($_.path)}|ForEach-Object{$_.path})
 $changed=@($now|Where-Object{$before.ContainsKey($_.path)-and $before[$_.path]-ne $_.sha256}|ForEach-Object{$_.path})
 $outOfScope=@()
 Get-ChildItem -LiteralPath $workspace -Recurse -File|ForEach-Object{
  $rel=$_.FullName.Substring($workspace.TrimEnd('\').Length+1).Replace('\','/')
  if($rel -match '^(smali[^/]*/|lib/|unknown/)'){$outOfScope+=$rel}
 }
 $signature="NOT TESTED • Android apksigner not found"
 $signer=Get-Command apksigner -ErrorAction SilentlyContinue
 if($signer){
  $verify=(& $signer.Source verify --verbose $output 2>&1|Out-String)
  if($LASTEXITCODE -eq 0){$signature="PASS • apksigner verified"}else{$signature="FAIL • unsigned/invalid signature"}
 }
 $report=[ordered]@{
  product="OMNI CYBER LAB • APK Resource Workbench"
  generatedUtc=[DateTime]::UtcNow.ToString("o")
  result=if($outOfScope.Count -eq 0){"PASS • archive built; runtime not tested"}else{"REVIEW • out-of-scope source edits detected"}
  sourceSha256=(Hash $source); outputSha256=(Hash $output)
  sourceHashMatchesWorkspace=((Hash $source)-eq $meta.sourceSha256)
  output=$output; apktoolVersion=$version
  validation=[ordered]@{archive="PASS";manifest="PASS";resourceTable="PASS";signature=$signature;runtime="NOT TESTED";install="NOT TESTED"}
  counts=[ordered]@{archiveEntries=$entries.Count;resourceFiles=$res.Count;dexFiles=$dex.Count;nativeLibraries=$native.Count}
  resourceChanges=[ordered]@{added=$added;removed=$removed;changed=$changed}
  outOfScopeFiles=$outOfScope
  limitations=@("Archive build success does not prove app runtime correctness.","Signature is NOT TESTED unless apksigner is installed and available on PATH.","Install, visual, localization and functional tests remain NOT TESTED until performed.")
 }
 $dir=Split-Path -Parent $output
 $json=Join-Path $dir "omni-resource-build-report.json"; $txt=Join-Path $dir "omni-resource-build-report.txt"
 $report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $json -Encoding UTF8
 $lines=@("OMNI CYBER LAB • RESOURCE REBUILD REPORT","Generated UTC: $($report.generatedUtc)","Result: $($report.result)","Source SHA-256: $($report.sourceSha256)","Output SHA-256: $($report.outputSha256)","Archive: PASS • Manifest: PASS • Resource table: PASS","Signature: $signature","Resources: $($res.Count) • DEX: $($dex.Count) • Native libs: $($native.Count)","Resource changes: added $($added.Count), removed $($removed.Count), changed $($changed.Count)","Out-of-scope files detected: $($outOfScope.Count)","","ADDED:",($added -join [Environment]::NewLine),"REMOVED:",($removed -join [Environment]::NewLine),"CHANGED:",($changed -join [Environment]::NewLine),"OUT OF SCOPE:",($outOfScope -join [Environment]::NewLine),"Runtime/install tests: NOT TESTED unless separately recorded.")
 $lines|Set-Content -LiteralPath $txt -Encoding UTF8
 Write-Host "JSON report: $json"; Write-Host "Text report: $txt"; Write-Host "Result: $($report.result)"
}
$java=Get-Command java -ErrorAction SilentlyContinue
if(!$java){throw "Java 17+ required."}
$javaVersion=(& java -version 2>&1|Out-String)
if($javaVersion -notmatch 'version "(1[7-9]|[2-9][0-9])'){throw "Java 17+ required. Detected: $javaVersion"}
$url="https://github.com/iBotPeaches/Apktool/releases/download/v$version/apktool_$version.jar"
if(!(Test-Path -LiteralPath $jar)){Invoke-WebRequest -Uri $url -OutFile $jar}
if((Hash $jar)-ne $expected){Remove-Item -LiteralPath $jar -Force;throw "Apktool JAR hash mismatch; download removed."}
$work=[IO.Path]::GetFullPath($WorkDir)
if($Action -eq "Decode"){
 if(!(Test-Path -LiteralPath $ApkPath -PathType Leaf)){throw "Source APK not found."}
 $source=(Resolve-Path -LiteralPath $ApkPath).Path
 if(Test-Path -LiteralPath $work){throw "WorkDir already exists; choose a new folder."}
 New-Item -ItemType Directory -Path $work|Out-Null
 & java -jar $jar d $source -o $work
 if($LASTEXITCODE -ne 0){throw "Apktool decode failed: exit $LASTEXITCODE"}
 $baseline=@(Inventory $work)
 [ordered]@{sourceApk=$source;sourceSha256=(Hash $source);apktoolVersion=$version;createdUtc=[DateTime]::UtcNow.ToString("o");authorization="Operator confirmed ownership or written permission";baselineInventory=$baseline}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $work "omni-workbench.json") -Encoding UTF8
 Write-Host "DECODE PASS • $work"; Write-Host "Edit res/ and assets/. Build creates a file-level change report."; exit 0
}
if(!(Test-Path -LiteralPath (Join-Path $work "apktool.yml"))){throw "Decoded Apktool workspace not found."}
$metaPath=Join-Path $work "omni-workbench.json"
if(!(Test-Path -LiteralPath $metaPath)){throw "OMNI metadata missing. Decode the source APK with this helper first."}
$meta=Get-Content -LiteralPath $metaPath -Raw|ConvertFrom-Json
if($meta.apktoolVersion -ne $version){throw "Workspace Apktool version mismatch."}
if(!(Test-Path -LiteralPath $meta.sourceApk -PathType Leaf)){throw "Original source APK missing; cannot produce a reliable comparison."}
if([string]::IsNullOrWhiteSpace($OutputApk)){$OutputApk=Join-Path (Split-Path -Parent $work) "omni-resource-rebuilt-unsigned.apk"}
$out=[IO.Path]::GetFullPath($OutputApk)
if($out -eq [IO.Path]::GetFullPath($meta.sourceApk)){throw "Output cannot overwrite source APK."}
if(Test-Path -LiteralPath $out){throw "Output exists; choose a new path. Existing files are never overwritten."}
Write-Host "Building decoded resources and binary manifest..."
& java -jar $jar b $work -o $out
if($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $out -PathType Leaf)){throw "Apktool build failed or output APK missing."}
BuildReport -source $meta.sourceApk -output $out -workspace $work -meta $meta
Write-Warning "Unsigned output: sign with your own keystore, verify using Android apksigner, then test on a controlled device. Re-signing changes update compatibility."
