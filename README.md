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
- Resource-table inspection with parser-reported locale configurations, localized manifest-label resolution where available, `resources.arsc` size/SHA-256, resource-file counts by type, `res/values*` configuration folders, bounded resource-path/size inventory and total declared resource bytes. The bounded resource-table parser enumerates package/type/resource IDs and per-configuration entries, resolves best-effort simple values, prints reference IDs and labels complex/map values without expanding them. Output is capped; this is not a complete Android resource compiler or editor.
- Structured static security checks with severity, evidence and remediation notes for debug flags, cleartext policy, backup configuration, sensitive permissions, exported components, signer availability and sampled code indicators.
- One-tap, non-invasive Security Test Orchestrator that runs a consolidated local package/manifest/permission/exported-component/signer/DEX-indicator review, saves timestamped per-package reports and exports a shareable result. Runtime, backend authorization and billing flows are explicitly marked NOT RUN rather than being reported as passing.
- Per-package regression history for the latest 10 local orchestrator snapshots. Consecutive runs compare newly observed rule matches, no-longer-matched signals and severity-label changes; history can be viewed in-app and exported as JSON. A no-longer-matched signal is explicitly not treated as proof of remediation.
- Per-finding remediation workflow labels (`OPEN`, `IN PROGRESS`, `READY TO RETEST`) are stored locally, shown in the findings dashboard, and included in JSON/PDF audit exports. These are owner-managed workflow states; none is an automatic fixed/verified status.
- Test Intelligence groups suite results into Permissions & Components, Network Security, Build & Integrity, Code & Package, Runtime & Backend, and Configuration, then prioritizes REVIEW signals and explicitly unrun/unavailable checks with suggested next steps. This is triage guidance, not an exploitability or risk score.
- Regression history checks the latest 10 snapshots for recurring rule-match titles: a signal present in an older snapshot, absent from the immediately previous run, and present again is labelled `REGRESSION`. This is a historical rule-match pattern, not proof that a vulnerability was fixed and reintroduced.
- Findings dashboard correlates saved runtime evidence/timeline text markers with broad finding categories (permissions, network/TLS, crash/ANR, storage, billing) and displays a per-app trend of rule-match counts from the latest 10 orchestrator snapshots. Correlation is keyword-based and the trend is not a vulnerability score or proof of causation.
- The one-tap orchestrator offers Quick, Standard and Comprehensive profiles. Quick covers core identity/build/network/permission/component checks; Standard adds bounded APK code/archive inventory; Comprehensive includes all configured static checks and explicitly labels runtime/backend checks that were not run. The selected profile is saved per package and recorded in each snapshot.
- Smali disassembly export and bounded Smali-to-DEX rebuild workflow.
- APK signing with a user-provided JKS/PKCS12 keystore using Android apksig.
- Static comparison of two APKs: package/version, signer, permissions, exported components and file hash.
- APK set backup ZIP with per-file SHA-256, archive readability, manifest presence, DEX/native-library counts, package/version and signer consistency notes.

### Advanced owner-authorized modification and billing labs

- **Advanced APK modification lab:** scans a bounded set of small text-like entries under `assets/` and `res/raw/`, lets the owner edit a selected entry, rebuilds the APK ZIP while preserving unchanged entries, removes stale APK signature blocks, calculates an output SHA-256 fingerprint, and exports an unsigned modified APK. The current text patcher has limits of 100 MB source APK, 256 KB edited entry, 8,000 ZIP entries, 30 MB per copied entry and 150 MB expanded output. Sign the output with your own keystore and validate it before installing.
- The patcher deliberately does not edit binary AndroidManifest.xml, compiled `resources.arsc`, layouts, icons, DEX, native libraries or third-party billing/license logic. Existing Smali DEX disassembly/rebuild and signing tools remain separate workflows. Full binary resource editing/recompilation is not implemented.
- **License / IAP emulation lab:** provides a locally persisted mock state machine for an owner-defined product ID, including purchased, pending, cancelled, expired, refunded/revoked, grace period, account hold, invalid license and restore events. It records a timestamped local event log per package. These are simulated QA events only; no Play Store request, receipt, payment, real entitlement or backend call is made.
- The simulator does not bypass licensing, fake a real Google Play receipt, or unlock paid features in another app. Production testing still requires Play Console license testers/test tracks, official Play Billing integration, server-side purchase-token verification, idempotent entitlement handling, acknowledgement/consumption, Real-time Developer Notifications and audit logs.

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
- Guided runtime test sessions with a per-package checklist, start timestamp, locally saved observations and progress indicator. The saved checklist state, start time and notes are also included in the shareable audit report/PDF export. When the owner explicitly taps **Attach latest diagnostics to session**, the latest available Shizuku package report and/or bounded process-log triage snapshot are stored locally with a timestamp (maximum 24 KB retained per package) and included in the report. The session also records an optional test-step/scenario label for each evidence attachment. A local event timeline records session start/restart, checklist marks/unmarks and evidence attachment timestamps; it is included in the audit export. A heuristic triage label highlights selected crash/ANR, TLS, permission and storage markers when present in the available process-log snapshot. It is not a numeric vulnerability score, a unique incident count or an automated security verdict. Process log snapshots request Android `threadtime` formatting and provide a structured count of matched crash/ANR, platform/permission, network/TLS, performance and storage indicators; counts are triage signals, not unique incident counts or a diagnosis. This is an owner-triggered evidence attachment, not background collection or autonomous dynamic analysis. Steps cover navigation, authentication/session handling, permissions, lifecycle, offline recovery, input validation, data exposure, deep links, crash observation and official purchase sandbox flows.
The per-app Security overview presents static finding counts, manual runtime-test coverage, evidence/timeline availability and user-managed review markers, with structured JSON export. It does not calculate a vulnerability score or claim that reviewed findings are remediated.

## Remediation retest queue

The per-app Security Findings Dashboard includes a guided retest queue for findings manually moved to `READY TO RETEST`. It provides category-specific suggestions for repeating an authorized check (permissions/components, network/TLS, build/signing, billing sandbox, storage/database, or runtime). The workflow can record `RETEST RECORDED • REVIEW` after a user reports attempting the retest, then return the item to `OPEN` for another remediation cycle. These are user-managed workflow states only: the app does not execute the retest, inspect a fix automatically, or mark a finding as passed or remediated.

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
- Binary manifest and selected compiled XML files are decoded for review. Resource inspection inventories archive paths/configurations and hashes the resource table, but complex resource maps are not expanded, reference chains are not recursively resolved, and resource editing or editable resource rebuild are not implemented.
- Smali output is bytecode disassembly, not Java/Kotlin source reconstruction. Rebuild changes DEX code only; it does not rebuild edited resources or binary manifests.
- Native library behavior, encrypted/obfuscated strings and runtime code paths are not comprehensively analyzed.
- HTTPS endpoint audit checks one manually supplied HTTPS URL. It does not crawl an app, intercept all device traffic, bypass TLS pinning or test authentication.
- Log snapshots are bounded and may omit short-lived or inaccessible log records. Categorized runtime triage is based only on a one-time 250-line process snapshot; it is not continuous monitoring or a malware verdict. Guided runtime sessions are manual checklists and local notes, not an automated test runner. Shizuku API compatibility can vary by version.
- Split restore requires a complete, compatible APK set and a matching signer/version. It does not restore private app data or guarantee compatibility with every OEM installer.
- Android controls package installation, user confirmation and uninstall permissions.
- Billing checklist items are manual test plans. The app does not unlock paid features, bypass license checks or verify real payment receipts.
- `QUERY_ALL_PACKAGES` is restricted by Google Play policy. Broad package visibility must be core functionality and may require policy approval; internal testing/sideloading is the initial target.

## Authorized use

Use only on devices, apps, networks and backend environments you own or are explicitly authorized to assess. No payment bypass, credential theft, malware execution, Wi-Fi attack or unauthorized endpoint testing is included.

This repository contains source code. A build is considered successful only when the matching GitHub Actions workflow reports success.
