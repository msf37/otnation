// Package analysis generates security findings from scan results.
package analysis

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

// AnalyzeAsset inspects scan results for the given asset and creates findings
// for detected exposures and security issues.
func AnalyzeAsset(ctx context.Context, st *store.Store, assetID uuid.UUID, identityID uuid.UUID) error {
	asset, err := st.GetAsset(ctx, assetID)
	if err != nil {
		return fmt.Errorf("analysis.AnalyzeAsset: load asset %s: %w", assetID, err)
	}

	scanResults, err := st.ListScanResults(ctx, assetID)
	if err != nil {
		return fmt.Errorf("analysis.AnalyzeAsset: list scan results: %w", err)
	}

	// Load existing findings to prevent duplicates.
	existingFindings, err := st.ListFindings(ctx, store.FindingFilters{
		AssetID: &assetID,
		Limit:   1000,
	})
	if err != nil {
		log.Warn().Err(err).Str("asset_id", assetID.String()).Msg("analysis: could not load existing findings")
	}
	existingTitles := make(map[string]bool, len(existingFindings))
	for _, f := range existingFindings {
		existingTitles[f.Title] = true
	}

	for _, sr := range scanResults {
		candidates := buildFindings(asset, sr, identityID)
		for _, f := range candidates {
			if existingTitles[f.Title] {
				continue
			}
			if _, err := st.InsertFinding(ctx, f); err != nil {
				log.Error().Err(err).
					Str("asset_id", assetID.String()).
					Str("title", f.Title).
					Msg("analysis: failed to insert finding")
				continue
			}
			existingTitles[f.Title] = true
			log.Info().
				Str("asset", asset.Value).
				Str("title", f.Title).
				Str("severity", string(f.Severity)).
				Msg("analysis: finding created")
		}
	}

	return nil
}

// buildFindings returns the set of findings that should be generated for
// the given asset and scan result, according to the detection rules.
func buildFindings(asset models.Asset, sr models.ScanResult, identityID uuid.UUID) []models.Finding {
	var findings []models.Finding

	srID := sr.ID

	// Evidence helper.
	evidence := func(extra map[string]interface{}) []byte {
		m := map[string]interface{}{
			"port":     sr.Port,
			"banner":   sr.Banner,
			"service":  sr.ServiceName,
			"category": sr.ServiceCategory,
		}
		for k, v := range extra {
			m[k] = v
		}
		b, _ := json.Marshal(m)
		return b
	}

	// Rule 1: Industrial protocol on public internet → critical.
	if asset.IsPublic && sr.ServiceCategory == models.ServiceCategoryIndustrialProtocol {
		findings = append(findings, models.Finding{
			IdentityID:   identityID,
			AssetID:      asset.ID,
			ScanResultID: &srID,
			Title:        "Exposed Industrial Protocol on Public Internet",
			Description: fmt.Sprintf(
				"Protocol %s detected on %s:%d. Industrial protocols should not be accessible from the internet.",
				sr.ServiceName, asset.Value, sr.Port,
			),
			Severity: models.SeverityCritical,
			Category: sr.ServiceCategory,
			Vendor:   sr.ServiceName,
			Protocol: sr.Protocol,
			Evidence: evidence(nil),
		})
	}

	// Rule 2: RDP exposed to internet → high.
	if sr.ServiceCategory == models.ServiceCategoryRemoteAccess && sr.Port == 3389 && asset.IsPublic {
		findings = append(findings, models.Finding{
			IdentityID:   identityID,
			AssetID:      asset.ID,
			ScanResultID: &srID,
			Title:        "RDP Exposed to Internet",
			Description:  fmt.Sprintf("Remote Desktop Protocol detected on %s:%d accessible from the internet.", asset.Value, sr.Port),
			Severity:     models.SeverityHigh,
			Category:     sr.ServiceCategory,
			Vendor:       "Microsoft",
			Protocol:     sr.Protocol,
			Evidence:     evidence(nil),
		})
	}

	// Rule 3: VNC exposed to internet → high.
	if sr.ServiceCategory == models.ServiceCategoryRemoteAccess && sr.Port == 5900 && asset.IsPublic {
		findings = append(findings, models.Finding{
			IdentityID:   identityID,
			AssetID:      asset.ID,
			ScanResultID: &srID,
			Title:        "VNC Exposed to Internet",
			Description:  fmt.Sprintf("VNC service detected on %s:%d accessible from the internet.", asset.Value, sr.Port),
			Severity:     models.SeverityHigh,
			Category:     sr.ServiceCategory,
			Protocol:     sr.Protocol,
			Evidence:     evidence(nil),
		})
	}

	// Rule 4: Telnet exposed; critical if industrial protocol.
	if sr.Port == 23 && asset.IsPublic {
		severity := models.SeverityHigh
		if sr.ServiceCategory == models.ServiceCategoryIndustrialProtocol {
			severity = models.SeverityCritical
		}
		findings = append(findings, models.Finding{
			IdentityID:   identityID,
			AssetID:      asset.ID,
			ScanResultID: &srID,
			Title:        "Telnet Service Exposed to Internet",
			Description:  fmt.Sprintf("Telnet service detected on %s:%d. Telnet transmits data in plaintext.", asset.Value, sr.Port),
			Severity:     severity,
			Category:     sr.ServiceCategory,
			Protocol:     sr.Protocol,
			Evidence:     evidence(nil),
		})
	}

	// Rule 5: Industrial web interface exposed → medium.
	if sr.ServiceCategory == models.ServiceCategoryWebInterface && asset.IsPublic && sr.Confidence > 0.7 {
		findings = append(findings, models.Finding{
			IdentityID:   identityID,
			AssetID:      asset.ID,
			ScanResultID: &srID,
			Title:        "Industrial Web Interface Exposed",
			Description:  fmt.Sprintf("Web interface detected on %s:%d accessible from the internet.", asset.Value, sr.Port),
			Severity:     models.SeverityMedium,
			Category:     sr.ServiceCategory,
			Protocol:     sr.Protocol,
			Evidence:     evidence(nil),
		})
	}

	// Rule 6: SSH detected → informational.
	if sr.ServiceCategory == models.ServiceCategoryRemoteAccess && sr.Port == 22 {
		findings = append(findings, models.Finding{
			IdentityID:   identityID,
			AssetID:      asset.ID,
			ScanResultID: &srID,
			Title:        "SSH Service Detected",
			Description:  fmt.Sprintf("SSH service detected on %s:%d.", asset.Value, sr.Port),
			Severity:     models.SeverityInformational,
			Category:     sr.ServiceCategory,
			Protocol:     sr.Protocol,
			Evidence:     evidence(nil),
		})
	}

	return findings
}
