param(
    [Parameter(Mandatory=$true)][ValidateSet("Decode","Build")][string]$Action,
    [Parameter(Mandatory=$true)][string]$ApkPath,
    [Parameter(Mandatory=$true)][string]$WorkDir,
    [string]$OutputApk = "",
    [switch]$ConfirmAuthorized
)

$ErrorActionPreference = "Stop"
if (-not $ConfirmAuthorized) {
    throw "Safety check: rerun with -ConfirmAuthorized only for an APK you own or have written permission to modify."
}
if (-not (Test-Path -LiteralPath $ApkPath -PathType Leaf) -and $Action -eq "Decode") {
    throw "Input APK does not exist: $ApkPath"
}
$apktoolVersion = "3.0.3"
$jarName = "apktool_$apktoolVersion.jar"
$jarPath = Join-Path $PSScriptRoot $jarName
$expectedSha256 = "dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423"
$downloadUrl = "https://github.com/iBotPeaches/Apktool/releases/download/v$apktoolVersion/$jarName"

$java = Get-Command java -ErrorAction SilentlyContinue
if (-not $java) { throw "Java runtime not found. Install a current Java 17+ runtime and reopen PowerShell." }
$javaVersion = (& java -version 2>&1 | Out-String)
if ($javaVersion -notmatch 'version "(1[7-9]|[2-9][0-9])') {
    throw "Java 17 or newer is required. Detected: $javaVersion"
}
if (-not (Test-Path -LiteralPath $jarPath)) {
    Write-Host "Downloading official Apktool $apktoolVersion..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $jarPath
}
$actualSha256 = (Get-FileHash -LiteralPath $jarPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
    Remove-Item -LiteralPath $jarPath -Force
    throw "Apktool SHA-256 verification failed. The downloaded JAR was deleted."
}

$resolvedWork = [System.IO.Path]::GetFullPath($WorkDir)
if ($Action -eq "Decode") {
    $resolvedApk = (Resolve-Path -LiteralPath $ApkPath).Path
    if (Test-Path -LiteralPath $resolvedWork) {
        throw "WorkDir already exists. Choose a new empty folder; the script will not overwrite existing work."
    }
    New-Item -ItemType Directory -Path $resolvedWork | Out-Null
    Write-Host "Decoding resources and manifest. This can take several minutes..."
    & java -jar $jarPath d $resolvedApk -o $resolvedWork
    if ($LASTEXITCODE -ne 0) { throw "Apktool decode failed with exit code $LASTEXITCODE." }
    $sourceHash = (Get-FileHash -LiteralPath $resolvedApk -Algorithm SHA256).Hash
    [ordered]@{
        sourceApk = $resolvedApk
        sourceSha256 = $sourceHash
        apktoolVersion = $apktoolVersion
        createdUtc = [DateTime]::UtcNow.ToString("o")
        authorization = "Operator confirmed ownership or written permission"
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $resolvedWork "omni-workbench.json") -Encoding UTF8
    Write-Host "Decode complete: $resolvedWork"
    Write-Host "Edit only permitted resources (for example res/values/strings.xml, res/drawable or res/mipmap) in this workspace."
    Write-Host "Do not alter payment, license, anti-tamper or entitlement code to access paid third-party content."
    exit 0
}

if (-not (Test-Path -LiteralPath (Join-Path $resolvedWork "apktool.yml") -PathType Leaf)) {
    throw "WorkDir must be an Apktool-decoded project containing apktool.yml."
}
$metaPath = Join-Path $resolvedWork "omni-workbench.json"
if (-not (Test-Path -LiteralPath $metaPath -PathType Leaf)) {
    throw "OMNI workbench metadata is missing. Decode the original APK with this helper first."
}
$metadata = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json
if ($metadata.apktoolVersion -ne $apktoolVersion) { throw "Workspace Apktool version mismatch." }
if ([string]::IsNullOrWhiteSpace($OutputApk)) { $OutputApk = Join-Path (Split-Path -Parent $resolvedWork) "omni-resource-rebuilt-unsigned.apk" }
$outputFull = [System.IO.Path]::GetFullPath($OutputApk)
Write-Host "Rebuilding decoded project into an unsigned APK..."
& java -jar $jarPath b $resolvedWork -o $outputFull
if ($LASTEXITCODE -ne 0) { throw "Apktool build failed with exit code $LASTEXITCODE." }
$hash = (Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash
Write-Host "Rebuild complete: $outputFull"
Write-Host "SHA-256: $hash"
Write-Warning "Output is unsigned. Sign with your own keystore, verify the signature, and install only on a device you control. Re-signing changes app identity and may prevent updates over the original installation."
