# OMNI APK Engineering Workbench (Windows + Android ARM64)

A desktop and on-device companion for full Android APK decode/rebuild in APKs you own or are explicitly authorized to modify. Apktool decodes DEX to Smali source and rebuilds Smali into DEX; it does not reconstruct original Java/Kotlin source. It uses the official Apktool 3.0.3 JAR and verifies its pinned SHA-256 before execution.

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

The tool decodes AndroidManifest.xml, resources.arsc, layouts, values, drawables, mipmaps, assets and DEX into Smali folders. It records the original APK SHA-256 and a baseline inventory.

## Edit and rebuild
Edit decoded res/, assets/ and Smali source folders (smali/, smali_classes2/, etc.), then run:

~~~powershell
.\Invoke-OmniApkResourceWorkbench.ps1 -Action Build -WorkDir "C:\OMNI\my-owner-app-work" -OutputApk "C:\OMNI\my-owner-app-rebuilt-unsigned.apk" -ConfirmAuthorized
~~~

The build produces an unsigned APK and two evidence files beside it:
- omni-resource-build-report.json — hashes, archive checks, signature status, resource counts and exact added/removed/changed resource paths.
- omni-resource-build-report.txt — concise human-readable build summary.

The report distinguishes archive/manifest/resource-table checks from signature verification and runtime/install tests. Signature is NOT TESTED unless Android apksigner is installed and available on PATH. Runtime and install tests are always NOT TESTED until separately performed. The original source APK is never overwritten, and an existing output path is never overwritten.

The workspace stores a baseline inventory so the report can show file-level changes. A changed resource or Smali file is not proof that the app behaves correctly; install on a controlled device and repeat visual, localization, accessibility and functional tests.

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
- On-device Android ARM64 full Apktool decode/rebuild: implemented through the Termux companion script; it decodes resources, manifest and DEX into Smali, then rebuilds them into an unsigned APK.
- APK signing: available in OMNI's Android signing workflow; desktop example uses apksigner.
- Automated install/runtime verification: not part of this script; report marks it NOT TESTED.


## On-device Android ARM64 rebuild (Termux companion)

The phone can decode and rebuild the full APK locally through Termux's native ARM64 toolchain, including Smali-to-DEX recompilation. This is an on-device companion workflow, not a claim that Apktool runs inside the OMNI Android process. It uses Termux packages and native AAPT2; the OMNI script checks the original APK hash, refuses to overwrite inputs/outputs, creates resource baselines and emits JSON + TXT evidence reports.

1. Install Termux from a trusted official distribution. Keep Termux and its plugins from the same distribution/signing source.
2. Download omni-apktool-android.sh from this repository into your phone's Download folder.
3. Open Termux and run:
~~~bash
termux-setup-storage
cd ~/storage/downloads
bash omni-apktool-android.sh setup
~~~
4. Put the APK you own in /sdcard/Download/OMNI-APK-Workbench/, then:
~~~bash
bash omni-apktool-android.sh decode /sdcard/Download/OMNI-APK-Workbench/my-owned-app.apk
~~~
5. Edit decoded res/, assets/ and Smali source folders (smali/, smali_classes2/, etc.) using a text editor/file manager, then rebuild:
~~~bash
bash omni-apktool-android.sh build /sdcard/Download/OMNI-APK-Workbench/my-owned-app-work
~~~
6. The script creates an unsigned rebuilt APK, a zip-aligned unsigned APK and JSON/TXT reports. Sign with your own keystore:
~~~bash
bash omni-apktool-android.sh sign /sdcard/Download/OMNI-APK-Workbench/my-owned-app-work-rebuilt-aligned-unsigned.apk /sdcard/Download/OMNI-APK-Workbench/owner-key.jks keyalias
~~~

Termux packages used: OpenJDK 21, Apktool, native AAPT2, zipalign, apksigner and Python. The script checks for ARM64 and explicitly passes the Termux native AAPT2 executable to Apktool to avoid an incompatible bundled desktop binary. Full decode uses Apktool's Smali output (not Java source); Apktool rebuild recompiles Smali into DEX along with resources and the binary manifest. The output remains unsigned until the separate sign command. Signature verification is performed after signing; runtime and install tests are not claimed by the build report.
