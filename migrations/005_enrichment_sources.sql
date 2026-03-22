-- Extend enrichment_source enum with new data sources.
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'securitytrails';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'crtsh';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'http_probe';
