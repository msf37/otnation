package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/cve"
	"github.com/otnation/platform/internal/exploitdb"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleCVECorrelate handles POST /api/v1/assets/{asset_id}/cve-correlate.
// Correlates open port banners + Shodan CVE IDs with NVD, fetches exploits
// for every CVE found, stores the enriched result, and creates findings.
func HandleCVECorrelate(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetID, err := parseUUID(mux.Vars(r)["asset_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset id")
			return
		}

		asset, err := st.GetAsset(r.Context(), assetID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "asset not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get asset")
			return
		}

		scanResults, err := st.ListScanResults(r.Context(), assetID)
		if err != nil {
			scanResults = nil
		}

		// Also pull known CVE IDs from Shodan enrichment.
		knownCVEIDs := extractShodanCVEIDs(r.Context(), st, assetID)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		result, err := cve.Correlate(ctx, asset.Value, scanResults, knownCVEIDs)
		if err != nil && !errors.Is(err, cve.ErrNoData) {
			log.Error().Err(err).Str("ip", asset.Value).Msg("cve: correlation failed")
			writeError(w, http.StatusBadGateway, "CVE correlation failed: "+err.Error())
			return
		}

		// Fetch exploits for every CVE in parallel (capped concurrency).
		enrichWithExploits(ctx, result)

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal CVE result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceCVECorrelation,
			Data:    rawData,
		}

		saved, err := st.UpsertEnrichment(r.Context(), rec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment record: "+err.Error())
			return
		}

		// Create findings for high/critical CVEs.
		var generatedFindings []models.Finding
		for _, svc := range result.Services {
			for _, c := range svc.CVEs {
				severity := cvssScoreToSeverity(c.CVSSScore)
				if severity != models.SeverityHigh && severity != models.SeverityCritical {
					continue
				}

				title := fmt.Sprintf("%s: %s", c.ID, truncateString(c.Description, 80))
				desc := fmt.Sprintf("CVE: %s\nService: %s (port %d)\nCVSS Score: %.1f\nDescription: %s\nReference: %s",
					c.ID, svc.Service, svc.Port, c.CVSSScore, c.Description, c.URL)

				exploitURLs := make([]string, 0, len(c.Exploits))
				for _, ex := range c.Exploits {
					exploitURLs = append(exploitURLs, ex.URL)
				}

				evidence := map[string]interface{}{
					"cve_id":       c.ID,
					"cvss_score":   c.CVSSScore,
					"port":         svc.Port,
					"service":      svc.Service,
					"url":          c.URL,
					"source":       "cve_correlation",
					"exploit_urls": exploitURLs,
					"exploit_count": len(c.Exploits),
				}
				evidenceBytes, _ := json.Marshal(evidence)

				finding := models.Finding{
					IdentityID:  asset.IdentityID,
					AssetID:     asset.ID,
					Title:       title,
					Description: desc,
					Severity:    severity,
					Category:    "vulnerability",
					Evidence:    evidenceBytes,
				}

				savedFinding, err := st.InsertFinding(r.Context(), finding)
				if err != nil {
					log.Debug().Err(err).Str("cve", c.ID).Msg("cve: skipped duplicate finding")
					continue
				}
				generatedFindings = append(generatedFindings, savedFinding)
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result":             saved,
			"findings_generated": len(generatedFindings),
			"findings":           generatedFindings,
		})
	}
}

// enrichWithExploits fetches Exploit-DB results for every CVE in the result,
// in parallel with a concurrency limit of 5, and attaches them in-place.
func enrichWithExploits(ctx context.Context, result *cve.Result) {
	if result == nil {
		return
	}

	type job struct {
		svcIdx int
		cveIdx int
		cveID  string
	}

	var jobs []job
	for si, svc := range result.Services {
		for ci, c := range svc.CVEs {
			// Only search if we don't already have exploits from NVD refs.
			if len(c.Exploits) == 0 {
				jobs = append(jobs, job{si, ci, c.ID})
			}
		}
	}
	if len(jobs) == 0 {
		return
	}

	sem := make(chan struct{}, 5)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, j := range jobs {
		j := j
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			exploits, err := exploitdb.Search(ctx, j.cveID)
			if err != nil {
				return
			}

			// Convert exploitdb.Exploit → cve.Exploit
			converted := make([]cve.Exploit, 0, len(exploits))
			for _, ex := range exploits {
				converted = append(converted, cve.Exploit{
					Source: "exploit-db",
					URL:    ex.URL,
					Title:  ex.Title,
				})
			}

			mu.Lock()
			result.Services[j.svcIdx].CVEs[j.cveIdx].Exploits = converted
			mu.Unlock()
		}()
	}
	wg.Wait()
}

// HandleGetCVECorrelate handles GET /api/v1/assets/{asset_id}/cve-correlate.
func HandleGetCVECorrelate(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetID, err := parseUUID(mux.Vars(r)["asset_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset id")
			return
		}

		records, err := st.GetEnrichment(r.Context(), assetID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeJSON(w, http.StatusOK, nil)
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get enrichment records")
			return
		}

		for _, rec := range records {
			if rec.Source == models.EnrichmentSourceCVECorrelation {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}

// cvssScoreToSeverity maps a CVSS score to a platform severity level.
func cvssScoreToSeverity(score float64) models.SeverityLevel {
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

// truncateString truncates a string to maxLen characters.
func truncateString(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// extractShodanCVEIDs reads the Shodan enrichment record for the asset and
// returns all unique CVE IDs found across top-level vulns and per-service vulns.
func extractShodanCVEIDs(ctx context.Context, st *store.Store, assetID [16]byte) []string {
	type shodanShape struct {
		Vulns []string `json:"vulns"`
		Data  []struct {
			Vulns map[string]interface{} `json:"vulns"`
		} `json:"data"`
	}

	records, err := st.GetEnrichment(ctx, assetID)
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var ids []string

	for _, rec := range records {
		if rec.Source != models.EnrichmentSourceShodan {
			continue
		}
		var shape shodanShape
		if err := json.Unmarshal(rec.Data, &shape); err != nil {
			continue
		}
		for _, id := range shape.Vulns {
			id = strings.ToUpper(strings.TrimSpace(id))
			if id != "" && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		for _, svc := range shape.Data {
			for id := range svc.Vulns {
				id = strings.ToUpper(strings.TrimSpace(id))
				if id != "" && !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}
