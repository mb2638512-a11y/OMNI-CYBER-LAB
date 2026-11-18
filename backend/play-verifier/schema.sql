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

-- Explicitly configured server-side consumable grants. Never accept coin/gold
-- amounts from a mobile client or from an unverified purchase payload.
CREATE TABLE IF NOT EXISTS wallet_product_grants (
    package_name TEXT NOT NULL,
    product_id TEXT NOT NULL,
    currency TEXT NOT NULL CHECK (currency ~ '^[A-Z0-9_]{2,16}$'),
    amount BIGINT NOT NULL CHECK (amount > 0 AND amount <= 1000000000),
    PRIMARY KEY (package_name, product_id)
);

CREATE TABLE IF NOT EXISTS wallet_balances (
    user_id TEXT NOT NULL,
    currency TEXT NOT NULL CHECK (currency ~ '^[A-Z0-9_]{2,16}$'),
    balance BIGINT NOT NULL DEFAULT 0 CHECK (balance >= 0 AND balance <= 9000000000000000),
    PRIMARY KEY (user_id, currency)
);

CREATE TABLE IF NOT EXISTS wallet_transactions (
    transaction_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    currency TEXT NOT NULL,
    amount BIGINT NOT NULL CHECK (amount > 0),
    direction TEXT NOT NULL CHECK (direction IN ('CREDIT', 'DEBIT')),
    source TEXT NOT NULL,
    purchase_token_sha256 TEXT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS wallet_transactions_user_time_idx
    ON wallet_transactions(user_id, created_at DESC);
