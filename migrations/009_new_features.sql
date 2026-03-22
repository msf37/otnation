-- Migration 009: attack_ttps on findings, scan_history, new enrichment sources

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS attack_ttps JSONB NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS scan_history (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    UUID        NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_date   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    open_ports  JSONB       NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_history_asset_id  ON scan_history (asset_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_scan_date ON scan_history (asset_id, scan_date DESC);

ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'iec104';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'modbus_deep';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'dnp3_deep';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'iccp';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'enip_deep';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'profinet';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'opcua';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'default_creds';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'censys';
