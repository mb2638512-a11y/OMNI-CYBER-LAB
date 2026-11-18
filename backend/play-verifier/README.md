# OMNI CYBER LAB — Google Play purchase verifier

This is a server-side reference service for apps you own or are authorized to assess. It verifies purchase tokens with the Google Play Developer API. The Android client must never contain the Google service-account private key.

## Required server environment

- `OMNI_VERIFIER_API_KEY`: high-entropy secret used by your trusted app backend to authenticate this service.
- `DATABASE_URL`: PostgreSQL connection string.
- `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON`: complete service-account JSON, injected as a server secret (never committed, bundled in an APK, or exposed to the client).
- `ALLOWED_PACKAGE_NAMES`: comma-separated exact package IDs.
- `ALLOWED_PRODUCT_IDS`: comma-separated exact product IDs.
- `PORT`: optional, defaults to 8080.

The service account must be granted the required Play Console access and the Android Publisher API must be enabled. Run `schema.sql` against PostgreSQL before starting the service.

## Endpoint

`POST /v1/play/verify`

Headers: `Authorization: Bearer <OMNI_VERIFIER_API_KEY>`, `Content-Type: application/json`.

Example body:

```json
{
  "packageName": "com.example.ownerapp",
  "productId": "premium.monthly",
  "purchaseToken": "PLAY_PURCHASE_TOKEN",
  "userId": "authenticated-user-id",
  "purchaseType": "subscription"
}
```

Use `purchaseType=product` for one-time products and `subscription` for subscriptions. Only exact allowlisted package and product IDs are accepted. The service calls Google Play Developer API; client-supplied price, balance, entitlement flags and purchase state are never trusted. Purchase tokens are SHA-256 hashed before persistence. A token already bound to another account is rejected; duplicate delivery is idempotent.

The service returns an entitlement decision only after Google verification. Pending/canceled products are not entitled. Subscription entitlement is based on the matching product line item, recognized state and unexpired period. Reconcile subscription changes and revocations using Real-time Developer Notifications (RTDN) in production; this minimal verifier does not yet implement the Pub/Sub RTDN receiver or automatic acknowledgement/consumption.

## Important production integration

- Put this service behind HTTPS and a trusted app backend. Do not embed `OMNI_VERIFIER_API_KEY` in a mobile app; the mobile app should call your own authenticated backend, which calls this service.
- Bind `userId` to a verified Firebase/Auth session on the trusted backend. Do not accept an arbitrary user ID from an untrusted client.
- Add rate limits, request IDs, structured audit logs, secret rotation and monitoring.
- Do not grant consumable coins/gold from a client balance. Fulfil consumables in a separate server-side wallet ledger using a unique transaction key and a database transaction. This endpoint verifies a purchase but does not mint currency.
- Keep test and production package IDs, products, service accounts and databases separate.
- The service does not bypass licensing, forge receipts or alter third-party app entitlements.

## Local build

```sh
go mod tidy
go test ./...
go run .
```


## Local Docker Compose

1. Copy `.env.example` to `.env` and replace every placeholder with your own values. Keep `.env` private and out of Git.
2. Ensure the Google service account is granted the required Play Console access and that the Android Publisher API is enabled.
3. Run `docker compose up --build -d` from this directory.
4. The verifier binds to `127.0.0.1:8080` for local testing. Put it behind a properly configured HTTPS reverse proxy before any remote use.
5. Configure product grants in PostgreSQL after the schema has been initialized. Example SQL is shown above.

The Compose file exposes the verifier only on loopback by default and persists PostgreSQL in a named volume. This is a starter deployment, not a complete production hardening baseline.
