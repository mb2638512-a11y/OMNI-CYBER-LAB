# OMNI CYBER LAB
Native Android defensive security-audit companion using Kotlin and Jetpack Compose.

## Implemented foundation
- Installed-package inventory and search.
- App version, requested permissions, exported component counts, debuggable flag and signer SHA-256.
- Optional Shizuku bridge with explicit user permission.
- Allowlisted read-only shell diagnostics: third-party package listing, Android release, SDK level and shell identity.
- Offline local inventory.
- GitHub Actions builds a debug APK and uploads it as an artifact.

## Build
Open in Android Studio with JDK 17, sync Gradle, connect a phone and press Run. Or open the Actions tab and download the APK artifact after a successful workflow.

## Shizuku setup
1. Install Shizuku from https://shizuku.rikka.app/.
2. Enable Developer options and Wireless debugging.
3. Follow Shizuku pairing instructions and start its service.
4. Open this app, tap Grant / Check and approve permission.
5. Run an allowlisted read-only diagnostic.

On non-rooted phones Shizuku relies on Wireless Debugging/ADB authorization. This app does not implement a standalone USB ADB host client; computer-side ADB uses Android Platform Tools separately.

## Limitations and safe use
Use only on devices, apps, networks and backend environments you own or are explicitly authorized to assess. Android sandboxing prevents reading other apps' private files, credentials, protected memory or hidden traffic. Exported components and permissions are review signals, not proof of vulnerabilities. No payment bypass, malware execution, Wi-Fi attack or unauthorized endpoint testing is included. Dynamic testing needs an owned app and dedicated test environment.

QUERY_ALL_PACKAGES is restricted by Google Play policy. Broad visibility must be core functionality and may require policy approval; initial use is intended for internal testing/sideloading.

This repository contains source. An APK is only considered built after the Actions workflow succeeds.
