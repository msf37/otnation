-- Deduplicate and add unique constraints for idempotent upserts.

-- DNS records: one record per (identity, type, name, value) tuple.
DELETE FROM dns_records
WHERE id NOT IN (
    SELECT DISTINCT ON (identity_id, record_type, name, value) id
    FROM dns_records
    ORDER BY identity_id, record_type, name, value, created_at
);
ALTER TABLE dns_records
    ADD CONSTRAINT dns_records_unique UNIQUE (identity_id, record_type, name, value);

-- Scan results: one result per (asset, port) — Shodan / scanner may both write to the same port.
ALTER TABLE scan_results
    DROP CONSTRAINT IF EXISTS scan_results_asset_port_unique;
ALTER TABLE scan_results
    ADD CONSTRAINT scan_results_asset_port_unique UNIQUE (asset_id, port);

-- Findings: prevent exact-duplicate titles per asset.
ALTER TABLE findings
    ADD CONSTRAINT findings_asset_title_unique UNIQUE (identity_id, asset_id, title);
