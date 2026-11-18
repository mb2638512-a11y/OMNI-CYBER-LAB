CREATE TABLE IF NOT EXISTS play_purchase_ledger (
    token_sha256 TEXT PRIMARY KEY,
    package_name TEXT NOT NULL,
    product_id TEXT NOT NULL,
    purchase_type TEXT NOT NULL CHECK (purchase_type IN ('product', 'subscription')),
    user_id TEXT NOT NULL,
    purchase_state TEXT NOT NULL,
    entitled BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS play_purchase_ledger_user_product_idx
    ON play_purchase_ledger(user_id, package_name, product_id);
