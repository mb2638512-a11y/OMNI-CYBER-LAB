# OMNI CYBER LAB — Adversarial Ads, VIP and Economy Test Plan

Scope: applications and backend environments owned by the operator or covered by written client authorization. Use a dedicated Play internal-testing track, staging package ID, staging database, test accounts and Google test ad units. Never point destructive tests at production users or real-money balances.

## Test boundaries and modes

- Static APK inspection: package/signature/resources/DEX/SDK markers. Heuristic findings are leads, not proof.
- Offline simulation: exercises expected policy decisions locally; it does not change the selected APK or a real entitlement.
- Staging integration: sends controlled test purchases and wallet operations to the owner's HTTPS staging backend.
- Live production verification: read-only checks first; no purchase, refund, ad-policy or balance changes without an approved change window.

## Ads — owner-controlled configuration

1. Use Google's official test ad unit IDs in debug/staging builds; verify production IDs are not shipped in debug configuration.
2. Verify remote-config values are typed, bounded, authenticated and have safe defaults.
3. Verify consent/age/privacy gating happens before ad SDK initialization where required.
4. Verify an ad-free entitlement is granted only from the trusted server's verified purchase record.
5. Tamper with local ad flags and cached remote-config values; the backend must not accept these as proof of paid ad-free status.
6. Test ad load failures, offline startup, SDK initialization failure and configuration rollback.
7. Verify the app's own ad-free policy hides its own ad placements after entitlement verification. Do not patch third-party ad SDKs or remove ads from unrelated installed apps.

## VIP / Google Play purchase security

- Fake client PURCHASED state without a valid token → reject.
- PENDING purchase → no entitlement.
- Canceled/refunded/revoked purchase → remove entitlement according to Play state and RTDN reconciliation.
- Expired subscription → no VIP.
- Wrong package, product ID or purchase type → reject.
- Token reused by another account → conflict.
- Duplicate notification or request → idempotent; no duplicate grant.
- Subscription state changes → reconcile from Google Play Developer API / RTDN, never from client flags.
- Keep service-account credentials and verifier API keys on the server only.

## Coins / gold / gems — staging economy

- Client-supplied credit amount → ignore; amount comes from server-side product configuration.
- Negative, zero, malformed or excessive spend → reject.
- Two simultaneous spends against one balance → atomic debit; never allow a negative balance.
- Replayed transaction ID or purchase token → no second credit/debit.
- Cross-user transaction replay → reject.
- Offline client balance edits → overwritten by authoritative server state on sync.
- Test grants must use a dedicated staging currency/account and must never be transferable to production.

## Required evidence

For each case record target package/version, signer fingerprint, environment, test account alias, UTC timestamp, request/response correlation ID, expected result, actual result, and sanitized logs. Never store raw purchase tokens, passwords, service-account JSON or payment details in the report.

## Current implementation status

The app includes a local adversarial scenario simulator and APK preflight inventory. The Go Play verifier calls Google Android Publisher API, enforces exact package/product allowlists, rejects pending/canceled one-time products, validates subscription product/expiry/state, hashes tokens, prevents cross-account token reuse, and fulfills configured consumables idempotently in a server-side ledger. Wallet spends use an atomic balance guard.

Not yet implemented: RTDN/Pub/Sub receiver and revocation reconciliation, automatic acknowledgement/consumption, full live staging orchestration from Android, and a first-party ad remote-config integration. The local simulator is not a live target test; mark integration tests only after running them against the configured staging backend.
