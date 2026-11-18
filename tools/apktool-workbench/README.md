# OMNI APK Resource Workbench (Windows)

This companion helper provides the full resource decode/edit/rebuild workflow using the official Apktool 3.0.3 command-line tool. It is separate from the Android app because Apktool is a Java desktop toolchain, not a lightweight Android resource-editing API.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- Java 17+
- An APK you own or have explicit written permission to modify

The script downloads Apktool from the official GitHub release and verifies its pinned SHA-256 before running it. Official release: https://github.com/iBotPeaches/Apktool/releases/tag/v3.0.3

## Decode

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-OmniApkResourceWorkbench.ps1 -Action Decode -ApkPath "C:\APK\my-owner-app.apk" -WorkDir "C:\OMNI\my-owner-app-work" -ConfirmAuthorized
```

Open the work folder and edit resources you are authorized to change, such as decoded XML under `res/values`, layouts, drawable and mipmap resources. The helper writes a metadata file with the source APK hash and tool version.

## Rebuild

```powershell
.\Invoke-OmniApkResourceWorkbench.ps1 -Action Build -ApkPath "C:\APK\my-owner-app.apk" -WorkDir "C:\OMNI\my-owner-app-work" -OutputApk "C:\OMNI\my-owner-app-rebuilt-unsigned.apk" -ConfirmAuthorized
```

The rebuilt APK is unsigned. Sign it with your own keystore using OMNI's existing APK signing workflow or Android SDK Build Tools, then verify the signature and test on a device you control.

## Scope

This helper is for legitimate resource engineering, localization, UI/branding experiments and security validation in owner-controlled apps. It is not a license/payment bypass tool. Do not use it to remove ads, unlock paid subscriptions, mint coins/gold, defeat anti-tamper or alter entitlements in third-party apps. For VIP, subscription and game-wallet security, use the Virtual Asset Security Lab's staging/test-account scenarios and server-side purchase verifier.
