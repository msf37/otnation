-- Add NERC CIP classification column to assets table.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS nerc_cip_classification JSONB DEFAULT '{}';
