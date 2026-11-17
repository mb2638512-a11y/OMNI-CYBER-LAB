# OMNI CYBER LAB

Native Android defensive security-audit companion built with Kotlin and Jetpack Compose. Designed for local inspection of installed apps and APK files, with optional Shizuku-assisted read-only diagnostics.

## Implemented capabilities

- Export audit summaries as shareable text and paginated PDF reports, including timestamped manual network/offline/privacy and billing checklist status plus any captured runtime/Shizuku evidence. Long lines are wrapped instead of silently truncated; checked checklist entries are explicitly identified as manual records.

### Device and installed-app inventory
- Installed-app inventory with launcher labels/icons, package IDs, version details, search, filters and app workspace navigation.
- Requested permission inventory and runtime permission grant state where Android exposes it.
- Exported Activity, Service, Receiver and Provider inventory, declared component permissions, debuggable state, backup/cleartext manifest flags and signing-certificate SHA-256.
- App launch and Android App Info settings shortcuts.
- Storage footprint lookup through Android Usage Access when the user grants it.

### APK inspection and engineering workflow
- Import an APK through Android's document picker and inspect metadata without installing or executing it.
- APK ZIP inventory: DEX files, native libraries, resource folder entries, assets, network security config and META-INF markers.
- Bounded DEX printable-string triage for selected API/behavior markers, URLs, credential-like patterns and common billing/ads/analytics SDK references.
- Resource-table locale/configuration inspection with localized manifest-label resolution where available (not full resource-ID enumeration or editing).
- Structured static security checks with severity, evidence and remediation notes for debug flags, cleartext policy, backup configuration, sensitive permissions, exported components, signer availability and sampled code indicators.
- Smali disassembly export and bounded Smali-to-DEX rebuild workflow.
- APK signing with a user-provided JKS/PKCS12 keystore using Android apksig.
- Static comparison of two APKs: package/version, signer, permissions, exported components and file hash.
- APK set backup ZIP with per-file SHA-256, archive readability, manifest presence, DEX/native-library counts, package/version and signer consistency notes.

### Install and restore
- Single APK install/update through Android's system Package Installer.
- Multi-APK split installation through Android PackageInstaller sessions when the complete base + split set is available.
- Split install preflight checks enforce one base APK, unique split names, matching package IDs, version codes and signing-certificate fingerprints.
- Split-set validation checks package identity, exactly one base APK, duplicate split names, matching version codes and matching signing certificates before a session is created.
- Android system confirmation and installer policy remain in control. The app does not silently install packages or bypass security prompts.

### Network and runtime diagnostics
- Manual HTTPS endpoint check for TLS protocol/cipher, peer certificate validity and selected response security headers.
- Optional Shizuku package diagnostics and bounded log snapshot for an app process, with common sensitive log patterns redacted.
- Categorized runtime log triage for crash/ANR, permission/platform, TLS/network, performance and storage/database indicators, with evidence counts and remediation hints.
- Manual billing sandbox, network, offline behavior and privacy review checklists. Progress is saved locally per package and survives app restarts; checked items remain manual records, not proof that a test actually passed.

## Build

Open the project in Android Studio with JDK 17, sync Gradle, connect a device and press Run. GitHub Actions runs the Android build and release workflows. Use the Actions page to inspect the exact commit and download artifacts when available.

## Shizuku setup

1. Install Shizuku from https://shizuku.rikka.app/.
2. Enable Developer options and Wireless debugging.
3. Follow Shizuku's pairing instructions and start its service.
4. Open OMNI CYBER LAB, tap Grant / Check and approve permission.
5. Run an explicitly authorized diagnostic.

On non-rooted phones Shizuku relies on Wireless Debugging/ADB authorization. Shizuku shell privileges are not equivalent to root and do not grant access to other apps' private data directories.

## Important limitations

- APK archive inventory, DEX string scans and structured security rules are static indicators, not a malware verdict or proof that an app is safe. No-match results do not establish that an app is secure.
- Binary manifest and selected compiled XML files are decoded for review. Complete resource-table resolution and editable resource rebuild are not yet implemented.
- Smali output is bytecode disassembly, not Java/Kotlin source reconstruction. Rebuild changes DEX code only; it does not rebuild edited resources or binary manifests.
- Native library behavior, encrypted/obfuscated strings and runtime code paths are not comprehensively analyzed.
- HTTPS endpoint audit checks one manually supplied HTTPS URL. It does not crawl an app, intercept all device traffic, bypass TLS pinning or test authentication.
- Log snapshots are bounded and may omit short-lived or inaccessible log records. Categorized runtime triage is based only on a one-time 250-line process snapshot; it is not continuous monitoring or a malware verdict. Shizuku API compatibility can vary by version.
- Split restore requires a complete, compatible APK set and a matching signer/version. It does not restore private app data or guarantee compatibility with every OEM installer.
- Android controls package installation, user confirmation and uninstall permissions.
- Billing checklist items are manual test plans. The app does not unlock paid features, bypass license checks or verify real payment receipts.
- `QUERY_ALL_PACKAGES` is restricted by Google Play policy. Broad package visibility must be core functionality and may require policy approval; internal testing/sideloading is the initial target.

## Authorized use

Use only on devices, apps, networks and backend environments you own or are explicitly authorized to assess. No payment bypass, credential theft, malware execution, Wi-Fi attack or unauthorized endpoint testing is included.

This repository contains source code. A build is considered successful only when the matching GitHub Actions workflow reports success.
