-- Extend enrichment_source enum with red-team data sources.
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'snmp';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'ot_probe';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'bgp';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'ip_whois';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'cve_correlation';
ALTER TYPE enrichment_source ADD VALUE IF NOT EXISTS 'vuln_notes';
