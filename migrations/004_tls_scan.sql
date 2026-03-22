-- TLS scan results per domain/subdomain asset.
CREATE TABLE IF NOT EXISTS tls_scan_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    identity_id     UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Certificate fields (empty string when scan failed)
    common_name     TEXT NOT NULL DEFAULT '',
    issuer          TEXT NOT NULL DEFAULT '',
    sans            JSONB NOT NULL DEFAULT '[]',
    not_before      TIMESTAMPTZ,
    not_after       TIMESTAMPTZ,
    days_until_expiry INTEGER,

    -- Protocol
    tls_version     TEXT NOT NULL DEFAULT '',
    cipher_suite    TEXT NOT NULL DEFAULT '',

    -- Key
    key_algorithm   TEXT NOT NULL DEFAULT '',
    key_size        INTEGER NOT NULL DEFAULT 0,
    signature_algo  TEXT NOT NULL DEFAULT '',

    -- Assessment
    grade           TEXT NOT NULL DEFAULT '',
    issues          JSONB NOT NULL DEFAULT '[]',
    error_msg       TEXT NOT NULL DEFAULT '',

    UNIQUE(asset_id)
);

CREATE INDEX IF NOT EXISTS tls_scan_results_identity_id_idx ON tls_scan_results(identity_id);
