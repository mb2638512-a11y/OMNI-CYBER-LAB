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

- APK before/after diff: compares ZIP-entry SHA-256 hashes and reports added, removed and changed entries, plus whole-file fingerprints; exports a text evidence report. This is a structural archive diff, not a semantic diff of compiled resources or a signature validation.
- Billing QA evidence can be exported as JSON, including package, test product ID, simulated entitlement state, generation time and local event-log lines. Subscription mock actions include renewal, pause and revoke in addition to purchase, pending, cancel, expiry, refund, grace period, hold, invalid-license and restore.
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

### Blind / black-box penetration-testing engagement workspace

- The per-app workspace includes a blind-testing engagement planner for client-scoped assessments. It records the target package/domain, allowed API hosts, excluded assets/functions, agreed test window/rate limits, operator authorization confirmation, manual coverage and evidence notes.
- The test matrix covers attack-surface mapping, authentication/session lifecycle, authorization boundaries, non-destructive input validation, deep links/intents, local data exposure, TLS, API entitlement enforcement, official billing sandbox flows, low-volume rate-limit assessment, approved tamper testing and detection/logging review.
- Exports a JSON engagement plan and evidence index. This is a manual test-planning and recordkeeping tool, not an automated exploit engine; checked items are not proof that a vulnerability exists or that a test passed.
- Black-box means the tester begins with limited internal knowledge and discovers the attack surface from the client-provided app and public-facing scope. Any stealth/low-noise behavior is constrained to the client-approved test window and assets.
### Live scoped black-box assessment and finding records

- The black-box engagement workspace includes a live HTTPS endpoint probe. It permits one GET or HEAD request per operator action, requires an HTTPS URL whose hostname exactly matches the client-entered allowlist, rejects URL-embedded credentials, uses 7-second connect/read timeouts, does not follow redirects, and reads at most 64 KB of response data.
- The probe records HTTP status, response time, content type/length, selected security headers, TLS protocol where the Android API level exposes it, cipher suite, peer certificate subject/issuer/SHA-256 and a SHA-256 digest of the bounded response body. It does not save response bodies or send custom authentication headers. Missing headers/status codes are evidence for review, not automatic vulnerability verdicts.
- Structured vulnerability records capture operator-assigned severity, reproduction preconditions/steps, observed impact/evidence reference, recommended remediation, timestamp and an explicit `UNVERIFIED • NEEDS REVIEW` state. Engagement JSON export includes the latest endpoint probe metadata and saved findings.
- This is a scoped endpoint metadata probe and evidence recorder, not a general-purpose fuzzer, credential tester, exploit launcher, API crawler or automated authorization bypass engine. Authenticated business-logic testing still needs client-provided test accounts and carefully designed, non-destructive test cases.
### Endpoint probe history and certificate lifecycle evidence

- The endpoint probe retains the latest 10 per-package observations, including HTTP status, latency, selected headers and peer certificate fingerprint. It flags a changed fingerprint between consecutive probes for operator review; certificate rotation is not automatically treated as an attack.
- Peer certificate evidence now includes validity against the device clock, not-before/not-after timestamps and estimated days remaining. Clock skew and certificate-chain/platform validation can affect interpretation; this is an observation aid, not a full PKI audit.
- The endpoint probe UI presents selected response-header observations and flags a peer certificate that is expired/not-yet-valid or within 30 days of expiry as a review signal. Missing headers are not automatically treated as vulnerabilities; applicability depends on whether the endpoint serves browser content, API traffic, or sensitive data.

### Static deep-link and app-link manifest analysis

- The decoded APK manifest report now extracts Activity intent filters containing `<data>` elements and summarizes declared actions, categories, URI schemes, hosts and path constraints.
- It prioritizes wildcard hosts, browsable custom schemes and HTTP schemes for manual review, and recommends validation of URI parsing, untrusted parameters, allowlists, authentication and object-level authorization.
- The analyzer is static and heuristic. It does not launch links, exercise target activities, prove that an entry point is exploitable, or verify runtime authorization. Android manifest data-tag merging and platform-version behavior may require manual confirmation.

### Client-scoped API authorization matrix

- The black-box workspace now records manual access-control test cases with a route/resource label, client-owned actor role, expected ALLOW/DENY behavior, operator-observed result, evidence reference and timestamp.
- Expected/observed mismatches are flagged as triage signals and retained in the engagement JSON export. The latest 100 cases are stored locally per package.
- This is a manual evidence matrix, not an API crawler or automatic IDOR/BOLA exploit. Use only client-provided test accounts and records; verify suspected authorization failures with repeatable evidence and server-side context.

### Authentication and session security test lab

- The black-box workspace includes manual test cases for secure token storage, logout invalidation, expiry, refresh rotation/replay, revocation, account switching, concurrent sessions, authentication error disclosure, app restart persistence, background-screen exposure and sensitive-action re-authentication.
- Operators record PASS, FAIL or NEEDS REVIEW with redacted evidence references. The latest 100 observations are stored locally per package and included in engagement JSON export.
- This module does not capture, replay, revoke or modify tokens and does not independently verify outcomes. Use client-owned test accounts, approved environments and redacted evidence; never store credentials or live tokens in notes.

### Local data security lab

- Adds manual review cases for plaintext preferences, app-private databases/backups, sensitive logs, clipboard, cache/temp files, shared storage, Android backup rules, screenshots/recent-app previews, Android Keystore use and account-switch/logout data isolation.
- Operators record PASS, FAIL, NEEDS REVIEW with redacted evidence references. Latest 100 observations are stored locally per package and included in the engagement JSON export.
- This is an evidence checklist, not a filesystem extraction or secret scanner. Do not place passwords, live tokens or personal data in notes.

### Network security review

- Adds manual checks for HTTPS-only API use, cleartext policy, TLS certificate validation, permissive trust managers, sensitive URL parameters, log/error leakage, redirect downgrade, server-side object authorization, response security/cache headers and fail-closed offline behavior.
- Latest 100 observations are stored locally per package and included in the engagement JSON export.
- This is a manual review workflow. It does not intercept arbitrary app traffic, bypass certificate validation, fuzz endpoints or perform automatic exploit attempts.

### Client engagement workspace

- Adds per-package client/organization, engagement title, optional purchase-order/reference and lifecycle status (PLANNED, ACTIVE, PAUSED, COMPLETED, CLOSED). Metadata is stored locally and included in engagement JSON exports.
- Keep client secrets and personal contact details out of local notes. This is a single-device workspace, not a multi-tenant hosted client portal.

### Purchase and subscription security lab

- Adds 12 manual lifecycle checks for backend purchase verification, pending purchases, acknowledgement/consumption, duplicate callbacks, restore, refunds/revocation, subscription expiry/grace/account hold, account switching, purchase-token validation and sandbox/production separation.
- Records PASS, FAIL, NEEDS REVIEW with redacted evidence references; latest 100 observations are saved locally and included in JSON exports.
- Use official billing sandbox and client-owned test accounts. No real payment is modified and no paid entitlement is bypassed.

### Vulnerability finding enrichment

- Structured findings now accept an optional CVSS v3.1 base score (validated to 0.0–10.0) and CWE reference, alongside severity, reproduction steps, impact/evidence and remediation.
- CVSS score and CWE are operator-entered metadata; the app does not calculate or independently validate a CVSS vector. Findings remain UNVERIFIED until supported by evidence and review.

### Finding remediation workflow

- Evidence-backed findings now show a per-finding workflow status: OPEN → IN PROGRESS → READY TO RETEST → RETEST RECORDED • REVIEW → CLOSED. Operators can advance or reopen a finding; status changes are timestamped and saved locally.
- A dashboard summary counts findings by workflow state. These are operator-managed workflow labels, not automatic proof of remediation or a passed retest. Use a fresh test and attach evidence before closing a finding.

### Professional client PDF report

- Adds a client-facing PDF export with client/engagement metadata, target and scope, authorization confirmation, attack-surface checklist coverage, finding details (severity, CVSS/CWE, reproduction, impact/evidence, remediation and workflow state), test-record counts and operator notes.
- The report explicitly documents limitations: operator-entered records are not independent certification, untested areas are not proven secure, and workflow labels are not independent retest verification.

### Engagement checkpoint history

- Operators can save up to 20 immutable local checkpoints of the current engagement workspace. Each checkpoint captures client/reference/status, target and scope, manual coverage, finding records, API authorization observations, session/local-data/network/billing test records, endpoint probe history and notes.
- The workspace displays the latest three checkpoints and includes the full checkpoint archive in JSON export; the PDF report indicates how many checkpoints have been saved.
- Checkpoints are snapshots, not isolated multi-engagement databases. They do not switch or restore a prior workspace, and all records remain on the device under the package-specific local preferences.

- The latest two checkpoints are compared in-app for coverage and test-record count changes, plus finding-title additions/removals. This is a lightweight historical comparison only: title absence is not evidence of remediation, and count deltas do not validate test quality.

### Isolated client engagement workspaces

- Adds a local workspace registry with separate per-engagement preference stores, create and switch controls. Existing package-level assessment data remains available as the Original workspace; newly created engagements keep their scope, findings, test records, evidence references and checkpoint history isolated from one another.
- Workspace registry and records remain on this Android device. This is not cloud sync, multi-user access control, encrypted client vault storage or a remote client portal. Use device security and avoid storing secrets or personal data.
### Workspace management

- Adds rename and confirmed-delete controls for non-original engagement workspaces. Deletion clears that engagement's local preference store and removes it from the workspace registry; the Original workspace is protected. Export reports before deleting a workspace.
- Workspace names are local labels. The feature does not provide encrypted evidence vaults, cloud backups, multi-user permissions or client portal access.
### Evidence vault, portfolio dashboard and encrypted backups

- Client workspaces include an app-private evidence vault. Attachments are encrypted individually with AES-256-GCM using a per-engagement Android Keystore key; each import is limited to 10 MB. Export creates a decrypted copy only at a user-selected destination. Workspace deletion removes the vault directory and its Keystore key.
- The client portfolio overview aggregates local counts across workspaces without merging their records.
- Client PDF reports include a confidential-review label, client/engagement reference, executive summary, coverage, severity counts, finding details and limitations.
- Workspace backup files use PBKDF2-HMAC-SHA256 (250,000 iterations) and AES-256-GCM with a user passphrase. Restore validates app package and workspace identity and resets authorization to false so the operator must reconfirm scope.
- Workspace preference backups do not include evidence file contents. Evidence attachments remain in the separate encrypted vault and must be exported individually. Backups are local files; no cloud sync is provided.