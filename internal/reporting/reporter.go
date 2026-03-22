// Package reporting provides CSV and JSON export functionality for assets and findings.
package reporting

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/otnation/platform/internal/store"
)

// Reporter wraps the store and provides export helpers.
type Reporter struct {
	store *store.Store
}

// New creates a Reporter backed by the given store.
func New(st *store.Store) *Reporter {
	return &Reporter{store: st}
}

// ExportAssetsJSON writes all assets for an identity as a JSON array to w.
func (r *Reporter) ExportAssetsJSON(ctx context.Context, identityID uuid.UUID, w io.Writer) error {
	assets, err := r.store.ListAssets(ctx, store.AssetFilters{
		IdentityID: &identityID,
		Limit:      100000,
		Page:       1,
	})
	if err != nil {
		return fmt.Errorf("reporting.ExportAssetsJSON: %w", err)
	}
	return json.NewEncoder(w).Encode(assets)
}

// ExportAssetsCSV writes all assets for an identity as CSV to w.
// Columns: id, type, value, country_code, asn, asn_org, is_public, provenance, created_at
func (r *Reporter) ExportAssetsCSV(ctx context.Context, identityID uuid.UUID, w io.Writer) error {
	assets, err := r.store.ListAssets(ctx, store.AssetFilters{
		IdentityID: &identityID,
		Limit:      100000,
		Page:       1,
	})
	if err != nil {
		return fmt.Errorf("reporting.ExportAssetsCSV: %w", err)
	}

	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"id", "type", "value", "country_code", "asn", "asn_org", "is_public", "provenance", "created_at"}); err != nil {
		return fmt.Errorf("reporting.ExportAssetsCSV write header: %w", err)
	}

	for _, a := range assets {
		asnStr := ""
		if a.ASN != nil {
			asnStr = fmt.Sprintf("%d", *a.ASN)
		}
		isPublic := "false"
		if a.IsPublic {
			isPublic = "true"
		}
		if err := cw.Write([]string{
			a.ID.String(),
			string(a.Type),
			a.Value,
			a.CountryCode,
			asnStr,
			a.ASNOrg,
			isPublic,
			a.Provenance,
			a.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}); err != nil {
			return fmt.Errorf("reporting.ExportAssetsCSV write row: %w", err)
		}
	}
	cw.Flush()
	return cw.Error()
}

// ExportFindingsJSON writes all findings for an identity as a JSON array to w.
func (r *Reporter) ExportFindingsJSON(ctx context.Context, identityID uuid.UUID, w io.Writer) error {
	findings, err := r.store.ListFindings(ctx, store.FindingFilters{
		IdentityID: &identityID,
		Limit:      100000,
		Page:       1,
	})
	if err != nil {
		return fmt.Errorf("reporting.ExportFindingsJSON: %w", err)
	}
	return json.NewEncoder(w).Encode(findings)
}

// ExportFindingsCSV writes all findings for an identity as CSV to w.
// Columns: id, title, severity, category, vendor, protocol, asset_id, created_at
func (r *Reporter) ExportFindingsCSV(ctx context.Context, identityID uuid.UUID, w io.Writer) error {
	findings, err := r.store.ListFindings(ctx, store.FindingFilters{
		IdentityID: &identityID,
		Limit:      100000,
		Page:       1,
	})
	if err != nil {
		return fmt.Errorf("reporting.ExportFindingsCSV: %w", err)
	}

	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"id", "title", "severity", "category", "vendor", "protocol", "asset_id", "created_at"}); err != nil {
		return fmt.Errorf("reporting.ExportFindingsCSV write header: %w", err)
	}

	for _, f := range findings {
		if err := cw.Write([]string{
			f.ID.String(),
			f.Title,
			string(f.Severity),
			f.Category,
			f.Vendor,
			f.Protocol,
			f.AssetID.String(),
			f.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}); err != nil {
			return fmt.Errorf("reporting.ExportFindingsCSV write row: %w", err)
		}
	}
	cw.Flush()
	return cw.Error()
}
