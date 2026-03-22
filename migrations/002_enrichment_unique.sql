-- =============================================================================
-- Migration: 002_enrichment_unique.sql
-- Add unique constraint on enrichment_records(asset_id, source) to support
-- the ON CONFLICT upsert in the store layer.
-- =============================================================================

ALTER TABLE enrichment_records
    ADD CONSTRAINT uq_enrichment_records_asset_source UNIQUE (asset_id, source);
