# OMNI APK Resource Workbench (Windows)

A desktop companion for full Android binary-resource engineering in APKs you own or are explicitly authorized to modify. It uses the official Apktool 3.0.3 JAR and verifies its pinned SHA-256 before execution.

## Requirements
- Windows PowerShell 5.1 or PowerShell 7
- Java 17+
- Android SDK Build Tools (apksigner recommended)
- An APK you own or have written permission to modify

## Decode
~~~powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-OmniApkResourceWorkbench.ps1 -Action Decode -ApkPath "C:\APK\my-owner-app.apk" -WorkDir "C:\OMNI\my-owner-app-work" -ConfirmAuthorized
~~~

The tool decodes AndroidManifest.xml, resources.arsc, layouts, values, drawables, mipmaps and other Apktool-supported resources. It records the original APK SHA-256 and a baseline inventory of resource files.

## Edit and rebuild
Edit decoded res/ and assets/ content, then run:

~~~powershell
.\Invoke-OmniApkResourceWorkbench.ps1 -Action Build -WorkDir "C:\OMNI\my-owner-app-work" -OutputApk "C:\OMNI\my-owner-app-rebuilt-unsigned.apk" -ConfirmAuthorized
~~~

The build produces an unsigned APK and two evidence files beside it:
- omni-resource-build-report.json — hashes, archive checks, signature status, resource counts and exact added/removed/changed resource paths.
- omni-resource-build-report.txt — concise human-readable build summary.

The report distinguishes archive/manifest/resource-table checks from signature verification and runtime/install tests. Signature is NOT TESTED unless Android apksigner is installed and available on PATH. Runtime and install tests are always NOT TESTED until separately performed. The original source APK is never overwritten, and an existing output path is never overwritten.

The workspace stores a baseline resource inventory so the report can show file-level changes. A changed resource file is not proof that the app behaves correctly; install on a controlled device and repeat visual, localization, accessibility and functional tests.

## Sign and verify
Use your own keystore and Android SDK Build Tools:

~~~powershell
apksigner sign --ks "C:\keys\owner-release.jks" --out "C:\OMNI\my-owner-app-signed.apk" "C:\OMNI\my-owner-app-rebuilt-unsigned.apk"
apksigner verify --verbose "C:\OMNI\my-owner-app-signed.apk"
~~~

Keep keystore passwords out of command history and never commit keystores or passwords to Git. Re-signing changes signing identity and may prevent updates over an existing installation.

## Scope and safety
This workbench is for resource engineering, localization, UI/branding experiments and security validation in owner-controlled apps. It is not a tool for removing ads, bypassing licenses or payments, altering third-party entitlements, defeating anti-tamper controls or minting virtual currency. Use the OMNI Virtual Asset Security Lab and staging/test accounts for purchase, subscription and game-economy integrity testing.

## Honest capability status
- Desktop binary resource decode/edit/rebuild: implemented through Apktool.
- On-device full Apktool resource rebuild: not implemented; Android app links to this Windows companion.
- APK signing: available in OMNI's Android signing workflow; desktop example uses apksigner.
- Automated install/runtime verification: not part of this script; report marks it NOT TESTED.
