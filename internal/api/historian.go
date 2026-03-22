package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/historian"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleHistorianDetect handles POST /api/v1/assets/{asset_id}/historian.
// Detects OT historian services on the asset IP, stores the result as enrichment,
// and creates a CRITICAL finding for any historian found.
func HandleHistorianDetect(st *store.Store) http.HandlerFunc {
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

		if asset.Type != models.AssetTypeIP {
			writeError(w, http.StatusBadRequest, "historian detection requires an IP asset")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		result, err := historian.Detect(ctx, asset.Value)
		if err != nil {
			if errors.Is(err, historian.ErrNoHistorian) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"result":   nil,
					"message":  "No OT historian services detected",
					"findings": []interface{}{},
				})
				return
			}
			log.Error().Err(err).Str("target", asset.Value).Msg("historian: detection failed")
			writeError(w, http.StatusInternalServerError, "historian detection failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceHistorian,
			Data:    rawData,
		}
		if _, err = st.UpsertEnrichment(r.Context(), rec); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment: "+err.Error())
			return
		}

		var generatedFindings []models.Finding
		for _, svc := range result.Services {
			title := fmt.Sprintf("OT Historian Exposed: %s (port %d)", svc.Product, svc.Port)
			desc := fmt.Sprintf(
				"An OT process historian (%s) was detected on %s port %d. "+
					"Historians store real-time and historical process data. "+
					"Unauthorized access may expose critical operational data.",
				svc.Product, asset.Value, svc.Port,
			)
			if svc.Banner != "" {
				desc += " Banner: " + svc.Banner
			}
			evidence := map[string]interface{}{
				"port":     svc.Port,
				"product":  svc.Product,
				"version":  svc.Version,
				"endpoint": svc.Endpoint,
				"banner":   svc.Banner,
				"source":   "historian",
			}
			evidenceBytes, _ := json.Marshal(evidence)
			f := models.Finding{
				IdentityID:  asset.IdentityID,
				AssetID:     asset.ID,
				Title:       title,
				Description: desc,
				Severity:    models.SeverityCritical,
				Category:    "ot",
				Protocol:    "historian",
				Evidence:    evidenceBytes,
			}
			saved, err := st.InsertFinding(r.Context(), f)
			if err != nil {
				log.Debug().Err(err).Str("title", title).Msg("historian: skipped duplicate finding")
			} else {
				generatedFindings = append(generatedFindings, saved)
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result":             result,
			"findings_generated": len(generatedFindings),
			"findings":           generatedFindings,
		})
	}
}

// HandleGetHistorian handles GET /api/v1/assets/{asset_id}/historian.
// Returns the stored historian enrichment record or null if not found.
func HandleGetHistorian(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceHistorian {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}
