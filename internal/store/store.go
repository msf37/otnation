// Package store provides the database access layer for the platform.
// All queries use pgx/v5 directly via a pgxpool.Pool.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/otnation/platform/internal/models"
)

// Store is the central data-access object backed by a PostgreSQL connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a Store from an existing pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func nullableUUID(id *uuid.UUID) interface{} {
	if id == nil {
		return nil
	}
	return *id
}

func nullableTime(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

// CreateIdentity inserts a new identity and returns it with the server-assigned
// id, created_at, and updated_at fields populated.
func (s *Store) CreateIdentity(ctx context.Context, name, orgName, notes, sector string, tags []byte) (models.Identity, error) {
	const q = `
		INSERT INTO identities (name, org_name, notes, sector, tags)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, org_name, COALESCE(notes,'') AS notes, tags,
		          COALESCE(sector,'') AS sector, created_at, updated_at`

	if tags == nil {
		tags = []byte("[]")
	}

	rows, err := s.pool.Query(ctx, q, name, orgName, notes, sector, tags)
	if err != nil {
		return models.Identity{}, fmt.Errorf("store.CreateIdentity query: %w", err)
	}
	identity, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Identity])
	if err != nil {
		return models.Identity{}, fmt.Errorf("store.CreateIdentity scan: %w", err)
	}
	return identity, nil
}

// GetIdentity retrieves a single identity by its UUID.
func (s *Store) GetIdentity(ctx context.Context, id uuid.UUID) (models.Identity, error) {
	const q = `
		SELECT id, name, org_name, COALESCE(notes,'') AS notes, tags,
		       COALESCE(sector,'') AS sector, created_at, updated_at
		FROM identities WHERE id = $1`

	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return models.Identity{}, fmt.Errorf("store.GetIdentity query: %w", err)
	}
	identity, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Identity])
	if err != nil {
		return models.Identity{}, fmt.Errorf("store.GetIdentity scan: %w", err)
	}
	return identity, nil
}

// ListIdentities returns all identities ordered by created_at desc.
func (s *Store) ListIdentities(ctx context.Context) ([]models.Identity, error) {
	const q = `
		SELECT id, name, org_name, COALESCE(notes,'') AS notes, tags,
		       COALESCE(sector,'') AS sector, created_at, updated_at
		FROM identities ORDER BY created_at DESC`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("store.ListIdentities query: %w", err)
	}
	identities, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.Identity])
	if err != nil {
		return nil, fmt.Errorf("store.ListIdentities scan: %w", err)
	}
	return identities, nil
}

// UpdateIdentity applies partial updates to name, org_name, notes, sector, and tags.
func (s *Store) UpdateIdentity(ctx context.Context, id uuid.UUID, name, orgName, notes, sector string, tags []byte) (models.Identity, error) {
	const q = `
		UPDATE identities
		SET name = $2, org_name = $3, notes = $4, sector = $5, tags = $6
		WHERE id = $1
		RETURNING id, name, org_name, COALESCE(notes,'') AS notes, tags,
		          COALESCE(sector,'') AS sector, created_at, updated_at`

	if tags == nil {
		tags = []byte("[]")
	}

	rows, err := s.pool.Query(ctx, q, id, name, orgName, notes, sector, tags)
	if err != nil {
		return models.Identity{}, fmt.Errorf("store.UpdateIdentity query: %w", err)
	}
	identity, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Identity])
	if err != nil {
		return models.Identity{}, fmt.Errorf("store.UpdateIdentity scan: %w", err)
	}
	return identity, nil
}

// DeleteIdentity removes an identity and all cascaded rows.
func (s *Store) DeleteIdentity(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM identities WHERE id = $1`
	ct, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("store.DeleteIdentity: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

// CreateSeed inserts a seed for the given identity.
func (s *Store) CreateSeed(ctx context.Context, identityID uuid.UUID, seedType models.SeedType, value string) (models.Seed, error) {
	const q = `
		INSERT INTO seeds (identity_id, type, value)
		VALUES ($1, $2, $3)
		RETURNING id, identity_id, type, value, created_at`

	rows, err := s.pool.Query(ctx, q, identityID, string(seedType), value)
	if err != nil {
		return models.Seed{}, fmt.Errorf("store.CreateSeed query: %w", err)
	}
	seed, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Seed])
	if err != nil {
		return models.Seed{}, fmt.Errorf("store.CreateSeed scan: %w", err)
	}
	return seed, nil
}

// ListSeeds returns all seeds for the given identity.
func (s *Store) ListSeeds(ctx context.Context, identityID uuid.UUID) ([]models.Seed, error) {
	const q = `
		SELECT id, identity_id, type, value, created_at
		FROM seeds WHERE identity_id = $1 ORDER BY created_at DESC`

	rows, err := s.pool.Query(ctx, q, identityID)
	if err != nil {
		return nil, fmt.Errorf("store.ListSeeds query: %w", err)
	}
	seeds, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.Seed])
	if err != nil {
		return nil, fmt.Errorf("store.ListSeeds scan: %w", err)
	}
	return seeds, nil
}

// DeleteSeed removes a single seed by its UUID.
func (s *Store) DeleteSeed(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM seeds WHERE id = $1`
	ct, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("store.DeleteSeed: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ---------------------------------------------------------------------------
// Asset
// ---------------------------------------------------------------------------

// AssetFilters holds optional filters for ListAssets / CountAssets.
type AssetFilters struct {
	IdentityID *uuid.UUID
	Type       string
	Country    string
	ASN        *int64
	Page       int // 1-based
	Limit      int
}

// UpsertAsset inserts a new asset or updates an existing one matched by
// (identity_id, type, value).
func (s *Store) UpsertAsset(ctx context.Context, a models.Asset) (models.Asset, error) {
	const q = `
		INSERT INTO assets
			(identity_id, type, value, provenance, is_public, is_cloud,
			 country_code, asn, asn_org, reverse_dns)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (identity_id, type, value) DO UPDATE
			SET provenance   = EXCLUDED.provenance,
			    is_public    = EXCLUDED.is_public,
			    is_cloud     = EXCLUDED.is_cloud,
			    country_code = EXCLUDED.country_code,
			    asn          = EXCLUDED.asn,
			    asn_org      = EXCLUDED.asn_org,
			    reverse_dns  = EXCLUDED.reverse_dns,
			    updated_at   = NOW()
		RETURNING id, identity_id, type, value, provenance, is_public, is_cloud,
		          COALESCE(country_code,'') AS country_code, asn,
		          COALESCE(asn_org,'') AS asn_org,
		          COALESCE(reverse_dns,'') AS reverse_dns,
		          created_at, updated_at`

	rows, err := s.pool.Query(ctx, q,
		a.IdentityID, string(a.Type), a.Value, a.Provenance,
		a.IsPublic, a.IsCloud, a.CountryCode, a.ASN, a.ASNOrg, a.ReverseDNS,
	)
	if err != nil {
		return models.Asset{}, fmt.Errorf("store.UpsertAsset query: %w", err)
	}
	asset, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Asset])
	if err != nil {
		return models.Asset{}, fmt.Errorf("store.UpsertAsset scan: %w", err)
	}
	return asset, nil
}

// GetAsset retrieves a single asset by its UUID.
func (s *Store) GetAsset(ctx context.Context, id uuid.UUID) (models.Asset, error) {
	const q = `
		SELECT id, identity_id, type, value, provenance, is_public, is_cloud,
		       COALESCE(country_code,'') AS country_code, asn,
		       COALESCE(asn_org,'') AS asn_org,
		       COALESCE(reverse_dns,'') AS reverse_dns,
		       created_at, updated_at
		FROM assets WHERE id = $1`

	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return models.Asset{}, fmt.Errorf("store.GetAsset query: %w", err)
	}
	asset, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Asset])
	if err != nil {
		return models.Asset{}, fmt.Errorf("store.GetAsset scan: %w", err)
	}
	return asset, nil
}

// ListAssets returns assets matching the supplied filters with pagination.
func (s *Store) ListAssets(ctx context.Context, f AssetFilters) ([]models.Asset, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	offset := (f.Page - 1) * f.Limit

	args := []interface{}{}
	where := "WHERE 1=1"
	n := 1

	if f.IdentityID != nil {
		where += fmt.Sprintf(" AND identity_id = $%d", n)
		args = append(args, *f.IdentityID)
		n++
	}
	if f.Type != "" {
		where += fmt.Sprintf(" AND type = $%d", n)
		args = append(args, f.Type)
		n++
	}
	if f.Country != "" {
		where += fmt.Sprintf(" AND country_code = $%d", n)
		args = append(args, f.Country)
		n++
	}
	if f.ASN != nil {
		where += fmt.Sprintf(" AND asn = $%d", n)
		args = append(args, *f.ASN)
		n++
	}

	args = append(args, f.Limit, offset)
	q := fmt.Sprintf(`
		SELECT id, identity_id, type, value, provenance, is_public, is_cloud,
		       COALESCE(country_code,'') AS country_code, asn,
		       COALESCE(asn_org,'') AS asn_org,
		       COALESCE(reverse_dns,'') AS reverse_dns,
		       created_at, updated_at
		FROM assets
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, n, n+1)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListAssets query: %w", err)
	}
	assets, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.Asset])
	if err != nil {
		return nil, fmt.Errorf("store.ListAssets scan: %w", err)
	}
	return assets, nil
}

// CountAssets returns the total number of assets matching the given filters.
func (s *Store) CountAssets(ctx context.Context, f AssetFilters) (int64, error) {
	args := []interface{}{}
	where := "WHERE 1=1"
	n := 1

	if f.IdentityID != nil {
		where += fmt.Sprintf(" AND identity_id = $%d", n)
		args = append(args, *f.IdentityID)
		n++
	}
	if f.Type != "" {
		where += fmt.Sprintf(" AND type = $%d", n)
		args = append(args, f.Type)
		n++
	}
	if f.Country != "" {
		where += fmt.Sprintf(" AND country_code = $%d", n)
		args = append(args, f.Country)
		n++
	}
	if f.ASN != nil {
		where += fmt.Sprintf(" AND asn = $%d", n)
		args = append(args, *f.ASN)
		n++
	}

	q := fmt.Sprintf("SELECT COUNT(*) FROM assets %s", where)
	var count int64
	err := s.pool.QueryRow(ctx, q, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store.CountAssets: %w", err)
	}
	return count, nil
}

// GetAssetByValue returns an asset matching the given identity and value.
func (s *Store) GetAssetByValue(ctx context.Context, identityID uuid.UUID, value string) (models.Asset, error) {
	const q = `
		SELECT id, identity_id, type, value, provenance, is_public, is_cloud,
		       COALESCE(country_code,'') AS country_code, asn,
		       COALESCE(asn_org,'') AS asn_org,
		       COALESCE(reverse_dns,'') AS reverse_dns,
		       created_at, updated_at
		FROM assets WHERE identity_id = $1 AND value = $2 LIMIT 1`

	rows, err := s.pool.Query(ctx, q, identityID, value)
	if err != nil {
		return models.Asset{}, fmt.Errorf("store.GetAssetByValue query: %w", err)
	}
	asset, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Asset])
	if err != nil {
		return models.Asset{}, fmt.Errorf("store.GetAssetByValue scan: %w", err)
	}
	return asset, nil
}

// ListSubdomainsByParent returns all subdomain assets whose value is a subdomain of parentDomain.
func (s *Store) ListSubdomainsByParent(ctx context.Context, identityID uuid.UUID, parentDomain string) ([]models.Asset, error) {
	const q = `
		SELECT id, identity_id, type, value, provenance, is_public, is_cloud,
		       COALESCE(country_code,'') AS country_code, asn,
		       COALESCE(asn_org,'') AS asn_org,
		       COALESCE(reverse_dns,'') AS reverse_dns,
		       created_at, updated_at
		FROM assets
		WHERE identity_id = $1
		  AND type IN ('subdomain')
		  AND value LIKE '%.' || $2
		ORDER BY value ASC`

	rows, err := s.pool.Query(ctx, q, identityID, parentDomain)
	if err != nil {
		return nil, fmt.Errorf("store.ListSubdomainsByParent query: %w", err)
	}
	assets, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.Asset])
	if err != nil {
		return nil, fmt.Errorf("store.ListSubdomainsByParent scan: %w", err)
	}
	return assets, nil
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

// InsertDNSRecord stores a DNS record, ignoring duplicates (idempotent).
func (s *Store) InsertDNSRecord(ctx context.Context, r models.DNSRecord) (models.DNSRecord, error) {
	const q = `
		INSERT INTO dns_records (identity_id, asset_id, record_type, name, value, resolved_ip)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (identity_id, record_type, name, value) DO UPDATE
			SET resolved_ip = EXCLUDED.resolved_ip
		RETURNING id, identity_id, asset_id, record_type, name, value,
		          COALESCE(resolved_ip,'') AS resolved_ip, created_at`

	rows, err := s.pool.Query(ctx, q,
		r.IdentityID, r.AssetID, r.RecordType, r.Name, r.Value, r.ResolvedIP,
	)
	if err != nil {
		return models.DNSRecord{}, fmt.Errorf("store.InsertDNSRecord query: %w", err)
	}
	rec, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.DNSRecord])
	if err != nil {
		return models.DNSRecord{}, fmt.Errorf("store.InsertDNSRecord scan: %w", err)
	}
	return rec, nil
}

// ListDNSRecords returns all DNS records for the given asset.
// For domain/subdomain assets: records where asset_id matches.
// For IP assets: records where resolved_ip matches the asset value.
func (s *Store) ListDNSRecords(ctx context.Context, assetID uuid.UUID) ([]models.DNSRecord, error) {
	const q = `
		SELECT dr.id, dr.identity_id, dr.asset_id, dr.record_type, dr.name, dr.value,
		       COALESCE(dr.resolved_ip,'') AS resolved_ip, dr.created_at
		FROM dns_records dr
		WHERE dr.asset_id = $1
		   OR dr.resolved_ip = (SELECT value FROM assets WHERE id = $1 AND type = 'ip')
		ORDER BY dr.record_type, dr.name, dr.created_at DESC`

	rows, err := s.pool.Query(ctx, q, assetID)
	if err != nil {
		return nil, fmt.Errorf("store.ListDNSRecords query: %w", err)
	}
	records, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.DNSRecord])
	if err != nil {
		return nil, fmt.Errorf("store.ListDNSRecords scan: %w", err)
	}
	return records, nil
}

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

// InsertScanResult stores a scan result; on port conflict it updates all fields
// so Shodan data (richer) always wins over raw scanner data.
func (s *Store) InsertScanResult(ctx context.Context, r models.ScanResult) (models.ScanResult, error) {
	const q = `
		INSERT INTO scan_results
			(asset_id, identity_id, port, protocol, service_name, banner,
			 service_category, confidence, raw_response, scanned_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (asset_id, port) DO UPDATE
			SET protocol         = EXCLUDED.protocol,
			    service_name     = EXCLUDED.service_name,
			    banner           = EXCLUDED.banner,
			    service_category = EXCLUDED.service_category,
			    confidence       = EXCLUDED.confidence,
			    raw_response     = EXCLUDED.raw_response,
			    scanned_at       = EXCLUDED.scanned_at
		RETURNING id, asset_id, identity_id, port, protocol,
		          COALESCE(service_name,'') AS service_name,
		          COALESCE(banner,'') AS banner,
		          COALESCE(service_category,'') AS service_category,
		          confidence, raw_response, scanned_at, created_at`

	scannedAt := r.ScannedAt
	if scannedAt.IsZero() {
		scannedAt = time.Now()
	}

	rows, err := s.pool.Query(ctx, q,
		r.AssetID, r.IdentityID, r.Port, r.Protocol,
		r.ServiceName, r.Banner, r.ServiceCategory, r.Confidence, r.RawResponse, scannedAt,
	)
	if err != nil {
		return models.ScanResult{}, fmt.Errorf("store.InsertScanResult query: %w", err)
	}
	result, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.ScanResult])
	if err != nil {
		return models.ScanResult{}, fmt.Errorf("store.InsertScanResult scan: %w", err)
	}
	return result, nil
}

// ListScanResults returns scan results for a given asset.
func (s *Store) ListScanResults(ctx context.Context, assetID uuid.UUID) ([]models.ScanResult, error) {
	const q = `
		SELECT id, asset_id, identity_id, port, protocol,
		       COALESCE(service_name,'') AS service_name,
		       COALESCE(banner,'') AS banner,
		       COALESCE(service_category,'') AS service_category,
		       confidence, raw_response, scanned_at, created_at
		FROM scan_results WHERE asset_id = $1 ORDER BY scanned_at DESC`

	rows, err := s.pool.Query(ctx, q, assetID)
	if err != nil {
		return nil, fmt.Errorf("store.ListScanResults query: %w", err)
	}
	results, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.ScanResult])
	if err != nil {
		return nil, fmt.Errorf("store.ListScanResults scan: %w", err)
	}
	return results, nil
}

// ListScanResultsByIdentity returns scan results for all assets under an identity.
func (s *Store) ListScanResultsByIdentity(ctx context.Context, identityID uuid.UUID) ([]models.ScanResult, error) {
	const q = `
		SELECT id, asset_id, identity_id, port, protocol,
		       COALESCE(service_name,'') AS service_name,
		       COALESCE(banner,'') AS banner,
		       COALESCE(service_category,'') AS service_category,
		       confidence, raw_response, scanned_at, created_at
		FROM scan_results WHERE identity_id = $1 ORDER BY scanned_at DESC`

	rows, err := s.pool.Query(ctx, q, identityID)
	if err != nil {
		return nil, fmt.Errorf("store.ListScanResultsByIdentity query: %w", err)
	}
	results, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.ScanResult])
	if err != nil {
		return nil, fmt.Errorf("store.ListScanResultsByIdentity scan: %w", err)
	}
	return results, nil
}

// UpdateScanResultByPort updates banner, service name, category and confidence
// for an existing scan result matched by (asset_id, port).
func (s *Store) UpdateScanResultByPort(ctx context.Context, assetID uuid.UUID, port int, sr models.ScanResult) error {
	const q = `
		UPDATE scan_results
		SET service_name     = $3,
		    banner           = $4,
		    service_category = $5,
		    confidence       = $6,
		    scanned_at       = $7
		WHERE asset_id = $1 AND port = $2`
	_, err := s.pool.Exec(ctx, q,
		assetID, port,
		sr.ServiceName, sr.Banner, sr.ServiceCategory, sr.Confidence, sr.ScannedAt,
	)
	if err != nil {
		return fmt.Errorf("store.UpdateScanResultByPort: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

// FindingFilters holds optional filters for ListFindings.
// FindingFilter is an alias kept for compatibility.
type FindingFilter = FindingFilters
type FindingFilters struct {
	IdentityID *uuid.UUID
	AssetID    *uuid.UUID
	Severity   string
	Vendor     string
	Protocol   string
	Page       int
	Limit      int
}

// InsertFinding stores a finding, updating evidence/description/severity on duplicate
// title per (identity_id, asset_id) so re-scans refresh stale data.
func (s *Store) InsertFinding(ctx context.Context, f models.Finding) (models.Finding, error) {
	const q = `
		INSERT INTO findings
			(identity_id, asset_id, scan_result_id, title, description,
			 severity, category, vendor, protocol, evidence, attack_ttps)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (identity_id, asset_id, title) DO UPDATE
			SET description  = EXCLUDED.description,
			    severity     = EXCLUDED.severity,
			    category     = EXCLUDED.category,
			    vendor       = EXCLUDED.vendor,
			    protocol     = EXCLUDED.protocol,
			    evidence     = EXCLUDED.evidence,
			    attack_ttps  = EXCLUDED.attack_ttps,
			    updated_at   = NOW()
		RETURNING id, identity_id, asset_id, scan_result_id, title,
		          COALESCE(description,'') AS description, severity,
		          COALESCE(category,'') AS category,
		          COALESCE(vendor,'') AS vendor,
		          COALESCE(protocol,'') AS protocol,
		          evidence, attack_ttps, created_at, updated_at`

	if f.Evidence == nil {
		f.Evidence = []byte("{}")
	}
	if f.AttackTTPs == nil {
		f.AttackTTPs = json.RawMessage("[]")
	}

	rows, err := s.pool.Query(ctx, q,
		f.IdentityID, f.AssetID, nullableUUID(f.ScanResultID),
		f.Title, f.Description, string(f.Severity),
		f.Category, f.Vendor, f.Protocol, f.Evidence, f.AttackTTPs,
	)
	if err != nil {
		return models.Finding{}, fmt.Errorf("store.InsertFinding query: %w", err)
	}
	finding, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Finding])
	if err != nil {
		return models.Finding{}, fmt.Errorf("store.InsertFinding scan: %w", err)
	}
	return finding, nil
}

// ListFindings returns findings matching the supplied filters.
func (s *Store) ListFindings(ctx context.Context, f FindingFilters) ([]models.Finding, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	offset := (f.Page - 1) * f.Limit

	args := []interface{}{}
	where := "WHERE 1=1"
	n := 1

	if f.IdentityID != nil {
		where += fmt.Sprintf(" AND identity_id = $%d", n)
		args = append(args, *f.IdentityID)
		n++
	}
	if f.AssetID != nil {
		where += fmt.Sprintf(" AND asset_id = $%d", n)
		args = append(args, *f.AssetID)
		n++
	}
	if f.Severity != "" {
		where += fmt.Sprintf(" AND severity = $%d", n)
		args = append(args, f.Severity)
		n++
	}
	if f.Vendor != "" {
		where += fmt.Sprintf(" AND vendor = $%d", n)
		args = append(args, f.Vendor)
		n++
	}
	if f.Protocol != "" {
		where += fmt.Sprintf(" AND protocol = $%d", n)
		args = append(args, f.Protocol)
		n++
	}

	args = append(args, f.Limit, offset)
	q := fmt.Sprintf(`
		SELECT id, identity_id, asset_id, scan_result_id, title,
		       COALESCE(description,'') AS description, severity,
		       COALESCE(category,'') AS category,
		       COALESCE(vendor,'') AS vendor,
		       COALESCE(protocol,'') AS protocol,
		       evidence, attack_ttps, created_at, updated_at
		FROM findings
		%s
		ORDER BY
		  CASE severity
		    WHEN 'critical' THEN 1
		    WHEN 'high'     THEN 2
		    WHEN 'medium'   THEN 3
		    WHEN 'low'      THEN 4
		    ELSE 5
		  END,
		  created_at DESC
		LIMIT $%d OFFSET $%d`, where, n, n+1)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListFindings query: %w", err)
	}
	findings, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.Finding])
	if err != nil {
		return nil, fmt.Errorf("store.ListFindings scan: %w", err)
	}
	return findings, nil
}

// GetFinding retrieves a single finding by its UUID.
func (s *Store) GetFinding(ctx context.Context, id uuid.UUID) (models.Finding, error) {
	const q = `
		SELECT id, identity_id, asset_id, scan_result_id, title,
		       COALESCE(description,'') AS description, severity,
		       COALESCE(category,'') AS category,
		       COALESCE(vendor,'') AS vendor,
		       COALESCE(protocol,'') AS protocol,
		       evidence, attack_ttps, created_at, updated_at
		FROM findings WHERE id = $1`

	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return models.Finding{}, fmt.Errorf("store.GetFinding query: %w", err)
	}
	finding, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Finding])
	if err != nil {
		return models.Finding{}, fmt.Errorf("store.GetFinding scan: %w", err)
	}
	return finding, nil
}

// UpdateFinding patches the status-adjacent mutable fields: description, severity, and evidence.
func (s *Store) UpdateFinding(ctx context.Context, id uuid.UUID, description string, severity models.SeverityLevel, evidence []byte) (models.Finding, error) {
	const q = `
		UPDATE findings
		SET description = $2, severity = $3, evidence = $4
		WHERE id = $1
		RETURNING id, identity_id, asset_id, scan_result_id, title,
		          COALESCE(description,'') AS description, severity,
		          COALESCE(category,'') AS category,
		          COALESCE(vendor,'') AS vendor,
		          COALESCE(protocol,'') AS protocol,
		          evidence, attack_ttps, created_at, updated_at`

	if evidence == nil {
		evidence = []byte("{}")
	}

	rows, err := s.pool.Query(ctx, q, id, description, string(severity), evidence)
	if err != nil {
		return models.Finding{}, fmt.Errorf("store.UpdateFinding query: %w", err)
	}
	finding, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Finding])
	if err != nil {
		return models.Finding{}, fmt.Errorf("store.UpdateFinding scan: %w", err)
	}
	return finding, nil
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

// CreateRun inserts a new run in pending status.
func (s *Store) CreateRun(ctx context.Context, identityID uuid.UUID, triggeredBy string) (models.Run, error) {
	const q = `
		INSERT INTO runs (identity_id, triggered_by)
		VALUES ($1, $2)
		RETURNING id, identity_id, status, started_at, ended_at,
		          triggered_by, stats, created_at`

	rows, err := s.pool.Query(ctx, q, identityID, triggeredBy)
	if err != nil {
		return models.Run{}, fmt.Errorf("store.CreateRun query: %w", err)
	}
	run, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Run])
	if err != nil {
		return models.Run{}, fmt.Errorf("store.CreateRun scan: %w", err)
	}
	return run, nil
}

// GetRun retrieves a single run by its UUID.
func (s *Store) GetRun(ctx context.Context, id uuid.UUID) (models.Run, error) {
	const q = `
		SELECT id, identity_id, status, started_at, ended_at,
		       triggered_by, stats, created_at
		FROM runs WHERE id = $1`

	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return models.Run{}, fmt.Errorf("store.GetRun query: %w", err)
	}
	run, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Run])
	if err != nil {
		return models.Run{}, fmt.Errorf("store.GetRun scan: %w", err)
	}
	return run, nil
}

// UpdateRun updates the status, started_at, ended_at, and stats of a run.
func (s *Store) UpdateRun(ctx context.Context, id uuid.UUID, status models.RunStatus, startedAt, endedAt *time.Time, stats []byte) (models.Run, error) {
	const q = `
		UPDATE runs
		SET status = $2, started_at = $3, ended_at = $4, stats = $5
		WHERE id = $1
		RETURNING id, identity_id, status, started_at, ended_at,
		          triggered_by, stats, created_at`

	if stats == nil {
		stats = []byte("{}")
	}

	rows, err := s.pool.Query(ctx, q, id, string(status), nullableTime(startedAt), nullableTime(endedAt), stats)
	if err != nil {
		return models.Run{}, fmt.Errorf("store.UpdateRun query: %w", err)
	}
	run, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Run])
	if err != nil {
		return models.Run{}, fmt.Errorf("store.UpdateRun scan: %w", err)
	}
	return run, nil
}

// ListRuns returns all runs for the given identity, newest first.
func (s *Store) ListRuns(ctx context.Context, identityID uuid.UUID) ([]models.Run, error) {
	const q = `
		SELECT id, identity_id, status, started_at, ended_at,
		       triggered_by, stats, created_at
		FROM runs WHERE identity_id = $1 ORDER BY created_at DESC`

	rows, err := s.pool.Query(ctx, q, identityID)
	if err != nil {
		return nil, fmt.Errorf("store.ListRuns query: %w", err)
	}
	runs, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.Run])
	if err != nil {
		return nil, fmt.Errorf("store.ListRuns scan: %w", err)
	}
	return runs, nil
}

// ---------------------------------------------------------------------------
// Job
// ---------------------------------------------------------------------------

// CreateJob inserts a new job into the jobs table.
func (s *Store) CreateJob(ctx context.Context, runID uuid.UUID, jobType string, payload []byte) (models.Job, error) {
	const q = `
		INSERT INTO jobs (run_id, type, payload)
		VALUES ($1, $2, $3)
		RETURNING id, run_id, type, status, payload, attempts, max_attempts,
		          COALESCE(error,'') AS error,
		          created_at, updated_at, started_at, ended_at`

	if payload == nil {
		payload = []byte("{}")
	}

	rows, err := s.pool.Query(ctx, q, runID, jobType, payload)
	if err != nil {
		return models.Job{}, fmt.Errorf("store.CreateJob query: %w", err)
	}
	job, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Job])
	if err != nil {
		return models.Job{}, fmt.Errorf("store.CreateJob scan: %w", err)
	}
	return job, nil
}

// ClaimNextJob atomically claims the oldest pending job using SKIP LOCKED.
// Returns pgx.ErrNoRows if no pending jobs exist.
func (s *Store) ClaimNextJob(ctx context.Context) (models.Job, error) {
	const q = `
		UPDATE jobs
		SET status = 'running', started_at = NOW(), attempts = attempts + 1, updated_at = NOW()
		WHERE id = (
			SELECT id FROM jobs
			WHERE status = 'pending'
			ORDER BY created_at
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, run_id, type, status, payload, attempts, max_attempts,
		          COALESCE(error,'') AS error,
		          created_at, updated_at, started_at, ended_at`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return models.Job{}, fmt.Errorf("store.ClaimNextJob query: %w", err)
	}
	job, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Job])
	if err != nil {
		return models.Job{}, fmt.Errorf("store.ClaimNextJob scan: %w", err)
	}
	return job, nil
}

// CompleteJob marks a job as completed.
func (s *Store) CompleteJob(ctx context.Context, id uuid.UUID) error {
	const q = `
		UPDATE jobs
		SET status = 'completed', ended_at = NOW(), updated_at = NOW()
		WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("store.CompleteJob: %w", err)
	}
	return nil
}

// FailJob marks a job as failed and stores the error message.
func (s *Store) FailJob(ctx context.Context, id uuid.UUID, errMsg string) error {
	const q = `
		UPDATE jobs
		SET status = 'failed', error = $2, ended_at = NOW(), updated_at = NOW()
		WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, id, errMsg)
	if err != nil {
		return fmt.Errorf("store.FailJob: %w", err)
	}
	return nil
}

// RetryJob resets a failed job back to pending so it can be retried.
func (s *Store) RetryJob(ctx context.Context, id uuid.UUID) error {
	const q = `
		UPDATE jobs
		SET status = 'pending', error = '', started_at = NULL, ended_at = NULL, updated_at = NOW()
		WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("store.RetryJob: %w", err)
	}
	return nil
}

// ListJobs returns all jobs belonging to a run.
func (s *Store) ListJobs(ctx context.Context, runID uuid.UUID) ([]models.Job, error) {
	const q = `
		SELECT id, run_id, type, status, payload, attempts, max_attempts,
		       COALESCE(error,'') AS error,
		       created_at, updated_at, started_at, ended_at
		FROM jobs WHERE run_id = $1 ORDER BY created_at`

	rows, err := s.pool.Query(ctx, q, runID)
	if err != nil {
		return nil, fmt.Errorf("store.ListJobs query: %w", err)
	}
	jobs, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.Job])
	if err != nil {
		return nil, fmt.Errorf("store.ListJobs scan: %w", err)
	}
	return jobs, nil
}

// ---------------------------------------------------------------------------
// EnrichmentRecord
// ---------------------------------------------------------------------------

// UpsertEnrichment inserts or updates an enrichment record for a given
// (asset_id, source) pair.
func (s *Store) UpsertEnrichment(ctx context.Context, r models.EnrichmentRecord) (models.EnrichmentRecord, error) {
	const q = `
		INSERT INTO enrichment_records (asset_id, source, data)
		VALUES ($1, $2, $3)
		ON CONFLICT (asset_id, source) DO UPDATE
			SET data = EXCLUDED.data, updated_at = NOW()
		RETURNING id, asset_id, source, data, created_at, updated_at`

	if r.Data == nil {
		r.Data = []byte("{}")
	}

	rows, err := s.pool.Query(ctx, q, r.AssetID, string(r.Source), r.Data)
	if err != nil {
		return models.EnrichmentRecord{}, fmt.Errorf("store.UpsertEnrichment query: %w", err)
	}
	rec, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.EnrichmentRecord])
	if err != nil {
		return models.EnrichmentRecord{}, fmt.Errorf("store.UpsertEnrichment scan: %w", err)
	}
	return rec, nil
}

// GetEnrichment retrieves the most recent enrichment record for an asset.
func (s *Store) GetEnrichment(ctx context.Context, assetID uuid.UUID) ([]models.EnrichmentRecord, error) {
	const q = `
		SELECT id, asset_id, source, data, created_at, updated_at
		FROM enrichment_records WHERE asset_id = $1 ORDER BY updated_at DESC`

	rows, err := s.pool.Query(ctx, q, assetID)
	if err != nil {
		return nil, fmt.Errorf("store.GetEnrichment query: %w", err)
	}
	records, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.EnrichmentRecord])
	if err != nil {
		return nil, fmt.Errorf("store.GetEnrichment scan: %w", err)
	}
	return records, nil
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TLSScanResult
// ---------------------------------------------------------------------------

// UpsertTLSScanResult inserts or replaces the TLS scan result for an asset.
func (s *Store) UpsertTLSScanResult(ctx context.Context, r models.TLSScanResult) (models.TLSScanResult, error) {
	const q = `
		INSERT INTO tls_scan_results
			(asset_id, identity_id, scanned_at, common_name, issuer, sans,
			 not_before, not_after, days_until_expiry,
			 tls_version, cipher_suite, key_algorithm, key_size, signature_algo,
			 grade, issues, error_msg)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (asset_id) DO UPDATE SET
			identity_id       = EXCLUDED.identity_id,
			scanned_at        = EXCLUDED.scanned_at,
			common_name       = EXCLUDED.common_name,
			issuer            = EXCLUDED.issuer,
			sans              = EXCLUDED.sans,
			not_before        = EXCLUDED.not_before,
			not_after         = EXCLUDED.not_after,
			days_until_expiry = EXCLUDED.days_until_expiry,
			tls_version       = EXCLUDED.tls_version,
			cipher_suite      = EXCLUDED.cipher_suite,
			key_algorithm     = EXCLUDED.key_algorithm,
			key_size          = EXCLUDED.key_size,
			signature_algo    = EXCLUDED.signature_algo,
			grade             = EXCLUDED.grade,
			issues            = EXCLUDED.issues,
			error_msg         = EXCLUDED.error_msg
		RETURNING id, asset_id, identity_id, scanned_at,
		          COALESCE(common_name,'') AS common_name,
		          COALESCE(issuer,'') AS issuer,
		          sans, not_before, not_after, days_until_expiry,
		          COALESCE(tls_version,'') AS tls_version,
		          COALESCE(cipher_suite,'') AS cipher_suite,
		          COALESCE(key_algorithm,'') AS key_algorithm,
		          key_size,
		          COALESCE(signature_algo,'') AS signature_algo,
		          COALESCE(grade,'') AS grade,
		          issues,
		          COALESCE(error_msg,'') AS error_msg`

	if r.SANs == nil {
		r.SANs = []byte("[]")
	}
	if r.Issues == nil {
		r.Issues = []byte("[]")
	}

	rows, err := s.pool.Query(ctx, q,
		r.AssetID, r.IdentityID, r.ScannedAt,
		r.CommonName, r.Issuer, r.SANs,
		r.NotBefore, r.NotAfter, r.DaysUntilExpiry,
		r.TLSVersion, r.CipherSuite, r.KeyAlgorithm, r.KeySize, r.SignatureAlgo,
		r.Grade, r.Issues, r.ErrorMsg,
	)
	if err != nil {
		return models.TLSScanResult{}, fmt.Errorf("store.UpsertTLSScanResult query: %w", err)
	}
	result, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.TLSScanResult])
	if err != nil {
		return models.TLSScanResult{}, fmt.Errorf("store.UpsertTLSScanResult scan: %w", err)
	}
	return result, nil
}

// GetTLSScanResult retrieves the stored TLS scan result for an asset.
func (s *Store) GetTLSScanResult(ctx context.Context, assetID uuid.UUID) (models.TLSScanResult, error) {
	const q = `
		SELECT id, asset_id, identity_id, scanned_at,
		       COALESCE(common_name,'') AS common_name,
		       COALESCE(issuer,'') AS issuer,
		       sans, not_before, not_after, days_until_expiry,
		       COALESCE(tls_version,'') AS tls_version,
		       COALESCE(cipher_suite,'') AS cipher_suite,
		       COALESCE(key_algorithm,'') AS key_algorithm,
		       key_size,
		       COALESCE(signature_algo,'') AS signature_algo,
		       COALESCE(grade,'') AS grade,
		       issues,
		       COALESCE(error_msg,'') AS error_msg
		FROM tls_scan_results WHERE asset_id = $1`

	rows, err := s.pool.Query(ctx, q, assetID)
	if err != nil {
		return models.TLSScanResult{}, fmt.Errorf("store.GetTLSScanResult query: %w", err)
	}
	result, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.TLSScanResult])
	if err != nil {
		return models.TLSScanResult{}, fmt.Errorf("store.GetTLSScanResult scan: %w", err)
	}
	return result, nil
}

// NameCount holds a name and its associated count for aggregated results.
type NameCount struct {
	Name  string `db:"name"  json:"name"`
	Count int64  `db:"count" json:"count"`
}

// CountryCount holds a country code and its asset count.
type CountryCount struct {
	CountryCode string `db:"country_code" json:"country_code"`
	Count       int64  `db:"count"        json:"count"`
}

// IdentityStats holds aggregated metrics for an identity.
type IdentityStats struct {
	TotalAssets        int64            `json:"total_assets"`
	TotalIPs           int64            `json:"total_ips"`
	TotalDomains       int64            `json:"total_domains"`
	OpenPorts          int64            `json:"open_ports"`
	FindingsBySeverity map[string]int64 `json:"findings_by_severity"`
	TopProtocols       []NameCount      `json:"top_protocols"`
	TopCountries       []CountryCount   `json:"top_countries"`
	RecentFindings     []models.Finding `json:"recent_findings"`
	RiskScore          float64          `json:"risk_score"`
}

// GetIdentityStats returns aggregated statistics for the given identity.
func (s *Store) GetIdentityStats(ctx context.Context, identityID uuid.UUID) (IdentityStats, error) {
	stats := IdentityStats{
		FindingsBySeverity: map[string]int64{
			"critical":      0,
			"high":          0,
			"medium":        0,
			"low":           0,
			"informational": 0,
		},
		TopProtocols:   []NameCount{},
		TopCountries:   []CountryCount{},
		RecentFindings: []models.Finding{},
	}

	// Asset counts by type.
	const assetCountQ = `
		SELECT type, COUNT(*) AS count
		FROM assets WHERE identity_id = $1
		GROUP BY type`
	rows, err := s.pool.Query(ctx, assetCountQ, identityID)
	if err != nil {
		return stats, fmt.Errorf("store.GetIdentityStats asset counts: %w", err)
	}
	for rows.Next() {
		var t string
		var c int64
		if err := rows.Scan(&t, &c); err != nil {
			rows.Close()
			return stats, fmt.Errorf("store.GetIdentityStats asset scan: %w", err)
		}
		stats.TotalAssets += c
		switch t {
		case "ip":
			stats.TotalIPs = c
		case "domain", "subdomain":
			stats.TotalDomains += c
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return stats, fmt.Errorf("store.GetIdentityStats asset rows: %w", err)
	}

	// Open ports (distinct port count across all scan results for this identity).
	const portsQ = `SELECT COUNT(DISTINCT port) FROM scan_results WHERE identity_id = $1`
	if err := s.pool.QueryRow(ctx, portsQ, identityID).Scan(&stats.OpenPorts); err != nil {
		return stats, fmt.Errorf("store.GetIdentityStats open ports: %w", err)
	}

	// Findings by severity.
	const severityQ = `
		SELECT severity, COUNT(*) AS count
		FROM findings WHERE identity_id = $1
		GROUP BY severity`
	sevRows, err := s.pool.Query(ctx, severityQ, identityID)
	if err != nil {
		return stats, fmt.Errorf("store.GetIdentityStats severity: %w", err)
	}
	for sevRows.Next() {
		var sev string
		var c int64
		if err := sevRows.Scan(&sev, &c); err != nil {
			sevRows.Close()
			return stats, fmt.Errorf("store.GetIdentityStats severity scan: %w", err)
		}
		stats.FindingsBySeverity[sev] = c
	}
	sevRows.Close()
	if err := sevRows.Err(); err != nil {
		return stats, fmt.Errorf("store.GetIdentityStats severity rows: %w", err)
	}

	// Top 5 protocols (service_name where service_name != '').
	const protoQ = `
		SELECT COALESCE(service_name, '') AS name, COUNT(*) AS count
		FROM scan_results
		WHERE identity_id = $1 AND service_name != ''
		GROUP BY service_name
		ORDER BY count DESC
		LIMIT 5`
	protoRows, err := s.pool.Query(ctx, protoQ, identityID)
	if err != nil {
		return stats, fmt.Errorf("store.GetIdentityStats protocols: %w", err)
	}
	for protoRows.Next() {
		var nc NameCount
		if err := protoRows.Scan(&nc.Name, &nc.Count); err != nil {
			protoRows.Close()
			return stats, fmt.Errorf("store.GetIdentityStats proto scan: %w", err)
		}
		stats.TopProtocols = append(stats.TopProtocols, nc)
	}
	protoRows.Close()
	if err := protoRows.Err(); err != nil {
		return stats, fmt.Errorf("store.GetIdentityStats proto rows: %w", err)
	}

	// Top 5 countries.
	const countryQ = `
		SELECT country_code, COUNT(*) AS count
		FROM assets
		WHERE identity_id = $1 AND country_code != ''
		GROUP BY country_code
		ORDER BY count DESC
		LIMIT 5`
	cRows, err := s.pool.Query(ctx, countryQ, identityID)
	if err != nil {
		return stats, fmt.Errorf("store.GetIdentityStats countries: %w", err)
	}
	for cRows.Next() {
		var cc CountryCount
		if err := cRows.Scan(&cc.CountryCode, &cc.Count); err != nil {
			cRows.Close()
			return stats, fmt.Errorf("store.GetIdentityStats country scan: %w", err)
		}
		stats.TopCountries = append(stats.TopCountries, cc)
	}
	cRows.Close()
	if err := cRows.Err(); err != nil {
		return stats, fmt.Errorf("store.GetIdentityStats country rows: %w", err)
	}

	// Recent 5 findings.
	const recentQ = `
		SELECT id, identity_id, asset_id, scan_result_id, title,
		       COALESCE(description,'') AS description, severity,
		       COALESCE(category,'') AS category,
		       COALESCE(vendor,'') AS vendor,
		       COALESCE(protocol,'') AS protocol,
		       evidence, attack_ttps, created_at, updated_at
		FROM findings
		WHERE identity_id = $1
		ORDER BY created_at DESC
		LIMIT 5`
	fRows, err := s.pool.Query(ctx, recentQ, identityID)
	if err != nil {
		return stats, fmt.Errorf("store.GetIdentityStats recent findings: %w", err)
	}
	findings, err := pgx.CollectRows(fRows, pgx.RowToStructByName[models.Finding])
	if err != nil {
		return stats, fmt.Errorf("store.GetIdentityStats recent findings scan: %w", err)
	}
	if findings != nil {
		stats.RecentFindings = findings
	}

	// Compute RiskScore from severity counts.
	critical := stats.FindingsBySeverity["critical"]
	high := stats.FindingsBySeverity["high"]
	medium := stats.FindingsBySeverity["medium"]
	low := stats.FindingsBySeverity["low"]
	score := float64(critical*10 + high*5 + medium*2 + low*1)

	// Boost score if OT ports are present.
	const otPortsQ = `
		SELECT COUNT(*) FROM scan_results sr
		JOIN assets a ON a.id = sr.asset_id
		WHERE a.identity_id = $1
		  AND sr.port = ANY($2::int[])`
	otPorts := []int32{502, 20000, 2404, 102, 44818}
	var otPortCount int64
	if err := s.pool.QueryRow(ctx, otPortsQ, identityID, otPorts).Scan(&otPortCount); err == nil && otPortCount > 0 {
		score *= 1.5
	}
	if score > 100 {
		score = 100
	}
	stats.RiskScore = score

	return stats, nil
}

// ---------------------------------------------------------------------------
// AuditLog
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// NERC CIP Classification
// ---------------------------------------------------------------------------

// UpdateAssetNERCCIP stores the NERC CIP classification for an asset.
// It upserts the data into the enrichment_records table using the "nerc_cip" source
// and also updates the nerc_cip_classification column on the assets table.
func (s *Store) UpdateAssetNERCCIP(ctx context.Context, assetID uuid.UUID, classification models.NERCCIPClassification) error {
	data, err := json.Marshal(classification)
	if err != nil {
		return fmt.Errorf("store.UpdateAssetNERCCIP marshal: %w", err)
	}

	const q = `
		UPDATE assets
		SET nerc_cip_classification = $2, updated_at = NOW()
		WHERE id = $1`
	_, err = s.pool.Exec(ctx, q, assetID, data)
	if err != nil {
		return fmt.Errorf("store.UpdateAssetNERCCIP: %w", err)
	}
	return nil
}

// GetAssetNERCCIP retrieves the NERC CIP classification for an asset.
func (s *Store) GetAssetNERCCIP(ctx context.Context, assetID uuid.UUID) (models.NERCCIPClassification, error) {
	const q = `SELECT COALESCE(nerc_cip_classification, '{}') FROM assets WHERE id = $1`
	var raw []byte
	if err := s.pool.QueryRow(ctx, q, assetID).Scan(&raw); err != nil {
		return models.NERCCIPClassification{}, fmt.Errorf("store.GetAssetNERCCIP: %w", err)
	}
	var c models.NERCCIPClassification
	if err := json.Unmarshal(raw, &c); err != nil {
		return models.NERCCIPClassification{}, fmt.Errorf("store.GetAssetNERCCIP unmarshal: %w", err)
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// Scan History
// ---------------------------------------------------------------------------

// InsertScanHistory records a snapshot of open ports for an asset.
func (s *Store) InsertScanHistory(ctx context.Context, assetID uuid.UUID, openPorts []byte) (models.ScanHistory, error) {
	const q = `
		INSERT INTO scan_history (asset_id, open_ports)
		VALUES ($1, $2)
		RETURNING id, asset_id, scan_date, open_ports, created_at`

	if openPorts == nil {
		openPorts = []byte("[]")
	}

	rows, err := s.pool.Query(ctx, q, assetID, openPorts)
	if err != nil {
		return models.ScanHistory{}, fmt.Errorf("store.InsertScanHistory query: %w", err)
	}
	sh, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.ScanHistory])
	if err != nil {
		return models.ScanHistory{}, fmt.Errorf("store.InsertScanHistory scan: %w", err)
	}
	return sh, nil
}

// GetLatestScanHistory returns the most recent scan history record for an asset.
func (s *Store) GetLatestScanHistory(ctx context.Context, assetID uuid.UUID) (models.ScanHistory, error) {
	const q = `
		SELECT id, asset_id, scan_date, open_ports, created_at
		FROM scan_history
		WHERE asset_id = $1
		ORDER BY scan_date DESC
		LIMIT 1`

	rows, err := s.pool.Query(ctx, q, assetID)
	if err != nil {
		return models.ScanHistory{}, fmt.Errorf("store.GetLatestScanHistory query: %w", err)
	}
	sh, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.ScanHistory])
	if err != nil {
		return models.ScanHistory{}, fmt.Errorf("store.GetLatestScanHistory scan: %w", err)
	}
	return sh, nil
}

// ListScanHistory returns all scan history records for an asset, ordered by scan_date descending.
func (s *Store) ListScanHistory(ctx context.Context, assetID uuid.UUID) ([]models.ScanHistory, error) {
	const q = `
		SELECT id, asset_id, scan_date, open_ports, created_at
		FROM scan_history
		WHERE asset_id = $1
		ORDER BY scan_date DESC`

	rows, err := s.pool.Query(ctx, q, assetID)
	if err != nil {
		return nil, fmt.Errorf("store.ListScanHistory query: %w", err)
	}
	history, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.ScanHistory])
	if err != nil {
		return nil, fmt.Errorf("store.ListScanHistory scan: %w", err)
	}
	return history, nil
}

// InsertAuditLog records an audit event.
func (s *Store) InsertAuditLog(ctx context.Context, entityType string, entityID uuid.UUID, action, actor string, details []byte) error {
	const q = `
		INSERT INTO audit_logs (entity_type, entity_id, action, actor, details)
		VALUES ($1, $2, $3, $4, $5)`

	if details == nil {
		details = []byte("{}")
	}

	_, err := s.pool.Exec(ctx, q, entityType, entityID, action, actor, details)
	if err != nil {
		return fmt.Errorf("store.InsertAuditLog: %w", err)
	}
	return nil
}
