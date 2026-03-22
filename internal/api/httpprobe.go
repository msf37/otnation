package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/httpprobe"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleHTTPProbe handles POST /api/v1/assets/{asset_id}/http-probe.
// Probes HTTP/HTTPS ports on the asset, stores the result as enrichment, and
// auto-generates findings for security issues found.
func HandleHTTPProbe(st *store.Store) http.HandlerFunc {
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

		// Load existing scan results to know which ports are open.
		scanResults, err := st.ListScanResults(r.Context(), assetID)
		if err != nil {
			scanResults = nil
		}
		var openPorts []int
		for _, sr := range scanResults {
			openPorts = append(openPorts, sr.Port)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		result, err := httpprobe.Probe(ctx, asset.Value, openPorts)
		if err != nil {
			log.Error().Err(err).Str("target", asset.Value).Msg("httpprobe: probe failed")
			writeError(w, http.StatusInternalServerError, "HTTP probe failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal probe result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceHTTPProbe,
			Data:    rawData,
		}

		_, err = st.UpsertEnrichment(r.Context(), rec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment record: "+err.Error())
			return
		}

		// Auto-generate findings.
		var generatedFindings []models.Finding
		for _, probe := range result.Probes {
			if probe.StatusCode == 0 {
				continue
			}

			isHTTPS := probe.StatusCode > 0 && (probe.Port == 443 || probe.Port == 8443)

			// Missing HSTS on HTTPS port.
			if isHTTPS && !probe.HSTS {
				f := insertHTTPProbeFinding(r.Context(), st, asset,
					"Missing HSTS Header",
					"The HTTPS service is not sending a Strict-Transport-Security header, allowing downgrade attacks.",
					models.SeverityMedium,
					"web",
					probe.Port,
				)
				if f != nil {
					generatedFindings = append(generatedFindings, *f)
				}
			}

			// Missing X-Frame-Options.
			if !probe.XFrameOptions && probe.StatusCode >= 200 && probe.StatusCode < 400 {
				f := insertHTTPProbeFinding(r.Context(), st, asset,
					"Missing X-Frame-Options Header",
					"The web service does not set an X-Frame-Options header, which may allow clickjacking attacks.",
					models.SeverityLow,
					"web",
					probe.Port,
				)
				if f != nil {
					generatedFindings = append(generatedFindings, *f)
				}
			}

			// Check interesting paths for critical exposures.
			for _, path := range probe.InterestingPaths {
				if path.StatusCode != http.StatusOK {
					continue
				}
				switch path.Path {
				case "/.git/HEAD":
					f := insertHTTPProbeFinding(r.Context(), st, asset,
						"Exposed Git Repository",
						"The /.git/HEAD file is publicly accessible, which may leak source code.",
						models.SeverityHigh,
						"web",
						probe.Port,
					)
					if f != nil {
						generatedFindings = append(generatedFindings, *f)
					}
				case "/admin":
					f := insertHTTPProbeFinding(r.Context(), st, asset,
						"Exposed Admin Panel",
						"The /admin path is publicly accessible.",
						models.SeverityMedium,
						"web",
						probe.Port,
					)
					if f != nil {
						generatedFindings = append(generatedFindings, *f)
					}
				case "/phpmyadmin":
					f := insertHTTPProbeFinding(r.Context(), st, asset,
						"Exposed phpMyAdmin",
						"The /phpmyadmin interface is publicly accessible and may allow database access.",
						models.SeverityHigh,
						"web",
						probe.Port,
					)
					if f != nil {
						generatedFindings = append(generatedFindings, *f)
					}
				case "/.env":
					f := insertHTTPProbeFinding(r.Context(), st, asset,
						"Exposed Environment File",
						"The /.env file is publicly accessible and likely contains sensitive credentials.",
						models.SeverityCritical,
						"web",
						probe.Port,
					)
					if f != nil {
						generatedFindings = append(generatedFindings, *f)
					}
				case "/actuator":
					f := insertHTTPProbeFinding(r.Context(), st, asset,
						"Exposed Spring Actuator",
						"The /actuator endpoint is publicly accessible and may expose sensitive application internals.",
						models.SeverityHigh,
						"web",
						probe.Port,
					)
					if f != nil {
						generatedFindings = append(generatedFindings, *f)
					}
				}
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result":             result,
			"findings_generated": len(generatedFindings),
			"findings":           generatedFindings,
		})
	}
}

// HandleGetHTTPProbe handles GET /api/v1/assets/{asset_id}/http-probe.
// Returns the stored HTTP probe enrichment record or null if not found.
func HandleGetHTTPProbe(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceHTTPProbe {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}

// insertHTTPProbeFinding creates a finding for an HTTP probe issue.
// Returns the inserted finding, or nil on failure (non-fatal).
func insertHTTPProbeFinding(ctx context.Context, st *store.Store, asset models.Asset, title, description string, severity models.SeverityLevel, category string, port int) *models.Finding {
	evidence := map[string]interface{}{
		"port":   port,
		"source": "http_probe",
	}
	evidenceBytes, _ := json.Marshal(evidence)

	finding := models.Finding{
		IdentityID:  asset.IdentityID,
		AssetID:     asset.ID,
		Title:       title,
		Description: description,
		Severity:    severity,
		Category:    category,
		Evidence:    evidenceBytes,
	}

	saved, err := st.InsertFinding(ctx, finding)
	if err != nil {
		log.Debug().Err(err).Str("title", title).Msg("httpprobe: skipped duplicate finding")
		return nil
	}
	return &saved
}
