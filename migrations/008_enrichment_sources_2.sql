-- Extend enrichment_source enum with new OT intel data sources.
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'iec61850';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'historian';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'hmi';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'icscert';
