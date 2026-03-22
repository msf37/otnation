-- =============================================================================
-- Migration: 001_init.sql
-- SCADA Exposure Discovery and Vulnerability Detection Platform
-- Initial schema
-- =============================================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------------
-- ENUM types
-- ---------------------------------------------------------------------------

CREATE TYPE seed_type         AS ENUM ('ip', 'cidr', 'domain');
CREATE TYPE asset_type        AS ENUM ('ip', 'domain', 'subdomain', 'endpoint');
CREATE TYPE enrichment_source AS ENUM ('internal', 'shodan', 'manual');
CREATE TYPE severity_level    AS ENUM ('critical', 'high', 'medium', 'low', 'informational');
CREATE TYPE run_status        AS ENUM ('pending', 'running', 'completed', 'failed');
CREATE TYPE job_status        AS ENUM ('pending', 'running', 'completed', 'failed', 'retrying');

-- ---------------------------------------------------------------------------
-- identities
-- ---------------------------------------------------------------------------

CREATE TABLE identities (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    org_name    TEXT        NOT NULL,
    notes       TEXT,
    tags        JSONB       NOT NULL DEFAULT '[]',
    sector      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_identities_name    ON identities (name);
CREATE INDEX idx_identities_sector  ON identities (sector);
CREATE INDEX idx_identities_tags    ON identities USING gin (tags);

-- ---------------------------------------------------------------------------
-- seeds
-- ---------------------------------------------------------------------------

CREATE TABLE seeds (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    type        seed_type   NOT NULL,
    value       TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (identity_id, type, value)
);

CREATE INDEX idx_seeds_identity_id ON seeds (identity_id);
CREATE INDEX idx_seeds_type        ON seeds (type);

-- ---------------------------------------------------------------------------
-- assets
-- ---------------------------------------------------------------------------

CREATE TABLE assets (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id  UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    type         asset_type  NOT NULL,
    value        TEXT        NOT NULL,
    provenance   TEXT        NOT NULL DEFAULT 'unknown',
    is_public    BOOLEAN     NOT NULL DEFAULT FALSE,
    is_cloud     BOOLEAN     NOT NULL DEFAULT FALSE,
    country_code TEXT,
    asn          BIGINT,
    asn_org      TEXT,
    reverse_dns  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (identity_id, type, value)
);

CREATE INDEX idx_assets_identity_id  ON assets (identity_id);
CREATE INDEX idx_assets_type         ON assets (type);
CREATE INDEX idx_assets_is_public    ON assets (is_public);
CREATE INDEX idx_assets_country_code ON assets (country_code);
CREATE INDEX idx_assets_asn          ON assets (asn);
CREATE INDEX idx_assets_value        ON assets (value);

-- ---------------------------------------------------------------------------
-- dns_records
-- ---------------------------------------------------------------------------

CREATE TABLE dns_records (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    asset_id    UUID        NOT NULL REFERENCES assets(id)     ON DELETE CASCADE,
    record_type TEXT        NOT NULL,   -- A, AAAA, CNAME, MX, TXT, etc.
    name        TEXT        NOT NULL,
    value       TEXT        NOT NULL,
    resolved_ip TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dns_records_identity_id  ON dns_records (identity_id);
CREATE INDEX idx_dns_records_asset_id     ON dns_records (asset_id);
CREATE INDEX idx_dns_records_record_type  ON dns_records (record_type);
CREATE INDEX idx_dns_records_name         ON dns_records (name);
CREATE INDEX idx_dns_records_resolved_ip  ON dns_records (resolved_ip);

-- ---------------------------------------------------------------------------
-- scan_results
-- ---------------------------------------------------------------------------

CREATE TABLE scan_results (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id         UUID        NOT NULL REFERENCES assets(id)     ON DELETE CASCADE,
    identity_id      UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    port             INTEGER     NOT NULL CHECK (port > 0 AND port <= 65535),
    protocol         TEXT        NOT NULL DEFAULT 'tcp',
    service_name     TEXT,
    banner           TEXT,
    service_category TEXT,
    confidence       DOUBLE PRECISION NOT NULL DEFAULT 0.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    raw_response     BYTEA,
    scanned_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_results_asset_id    ON scan_results (asset_id);
CREATE INDEX idx_scan_results_identity_id ON scan_results (identity_id);
CREATE INDEX idx_scan_results_port        ON scan_results (port);
CREATE INDEX idx_scan_results_protocol    ON scan_results (protocol);
CREATE INDEX idx_scan_results_scanned_at  ON scan_results (scanned_at);

-- ---------------------------------------------------------------------------
-- enrichment_records
-- ---------------------------------------------------------------------------

CREATE TABLE enrichment_records (
    id          UUID               PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    UUID               NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source      enrichment_source  NOT NULL DEFAULT 'internal',
    data        JSONB              NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ        NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ        NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_enrichment_records_asset_id ON enrichment_records (asset_id);
CREATE INDEX idx_enrichment_records_source   ON enrichment_records (source);
CREATE INDEX idx_enrichment_records_data     ON enrichment_records USING gin (data);

-- ---------------------------------------------------------------------------
-- findings
-- ---------------------------------------------------------------------------

CREATE TABLE findings (
    id             UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id    UUID           NOT NULL REFERENCES identities(id)  ON DELETE CASCADE,
    asset_id       UUID           NOT NULL REFERENCES assets(id)      ON DELETE CASCADE,
    scan_result_id UUID           REFERENCES scan_results(id)         ON DELETE SET NULL,
    title          TEXT           NOT NULL,
    description    TEXT,
    severity       severity_level NOT NULL DEFAULT 'informational',
    category       TEXT,
    vendor         TEXT,
    protocol       TEXT,
    evidence       JSONB          NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_identity_id    ON findings (identity_id);
CREATE INDEX idx_findings_asset_id       ON findings (asset_id);
CREATE INDEX idx_findings_scan_result_id ON findings (scan_result_id);
CREATE INDEX idx_findings_severity       ON findings (severity);
CREATE INDEX idx_findings_category       ON findings (category);
CREATE INDEX idx_findings_vendor         ON findings (vendor);
CREATE INDEX idx_findings_protocol       ON findings (protocol);

-- ---------------------------------------------------------------------------
-- runs
-- ---------------------------------------------------------------------------

CREATE TABLE runs (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id  UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    status       run_status  NOT NULL DEFAULT 'pending',
    started_at   TIMESTAMPTZ,
    ended_at     TIMESTAMPTZ,
    triggered_by TEXT        NOT NULL DEFAULT 'api',
    stats        JSONB       NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_runs_identity_id ON runs (identity_id);
CREATE INDEX idx_runs_status      ON runs (status);
CREATE INDEX idx_runs_created_at  ON runs (created_at);

-- ---------------------------------------------------------------------------
-- jobs
-- ---------------------------------------------------------------------------

CREATE TABLE jobs (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id       UUID        NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    type         TEXT        NOT NULL,
    status       job_status  NOT NULL DEFAULT 'pending',
    payload      JSONB       NOT NULL DEFAULT '{}',
    attempts     INTEGER     NOT NULL DEFAULT 0,
    max_attempts INTEGER     NOT NULL DEFAULT 3,
    error        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at   TIMESTAMPTZ,
    ended_at     TIMESTAMPTZ
);

CREATE INDEX idx_jobs_run_id     ON jobs (run_id);
CREATE INDEX idx_jobs_type       ON jobs (type);
CREATE INDEX idx_jobs_status     ON jobs (status);
CREATE INDEX idx_jobs_created_at ON jobs (created_at);

-- ---------------------------------------------------------------------------
-- audit_logs
-- ---------------------------------------------------------------------------

CREATE TABLE audit_logs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type TEXT        NOT NULL,
    entity_id   UUID        NOT NULL,
    action      TEXT        NOT NULL,
    actor       TEXT        NOT NULL DEFAULT 'system',
    details     JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_entity_type ON audit_logs (entity_type);
CREATE INDEX idx_audit_logs_entity_id   ON audit_logs (entity_id);
CREATE INDEX idx_audit_logs_action      ON audit_logs (action);
CREATE INDEX idx_audit_logs_actor       ON audit_logs (actor);
CREATE INDEX idx_audit_logs_created_at  ON audit_logs (created_at);

-- ---------------------------------------------------------------------------
-- updated_at auto-update trigger
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION trigger_set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER set_updated_at_identities
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

CREATE TRIGGER set_updated_at_assets
    BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

CREATE TRIGGER set_updated_at_enrichment_records
    BEFORE UPDATE ON enrichment_records
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

CREATE TRIGGER set_updated_at_findings
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

CREATE TRIGGER set_updated_at_jobs
    BEFORE UPDATE ON jobs
    FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();
