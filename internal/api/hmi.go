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
	"github.com/otnation/platform/internal/hmi"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleHMIFingerprint handles POST /api/v1/assets/{asset_id}/hmi.
// Fingerprints SCADA HMI software on the asset IP, stores the result as enrichment,
// and creates a HIGH finding per HMI detected.
func HandleHMIFingerprint(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "HMI fingerprinting requires an IP asset")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		result, err := hmi.Fingerprint(ctx, asset.Value)
		if err != nil {
			if errors.Is(err, hmi.ErrNoHMI) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"result":   nil,
					"message":  "No SCADA HMI software detected",
					"findings": []interface{}{},
				})
				return
			}
			log.Error().Err(err).Str("target", asset.Value).Msg("hmi: fingerprint failed")
			writeError(w, http.StatusInternalServerError, "HMI fingerprint failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceHMI,
			Data:    rawData,
		}
		if _, err = st.UpsertEnrichment(r.Context(), rec); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment: "+err.Error())
			return
		}

		var generatedFindings []models.Finding
		for _, h := range result.HMIs {
			title := fmt.Sprintf("SCADA HMI Exposed: %s / %s (port %d)", h.Vendor, h.Product, h.Port)
			desc := fmt.Sprintf(
				"%s %s was detected on %s port %d. %s",
				h.Vendor, h.Product, asset.Value, h.Port, h.RiskNote,
			)
			if h.Evidence != "" {
				desc += " Evidence: " + h.Evidence
			}
			evidence := map[string]interface{}{
				"port":      h.Port,
				"product":   h.Product,
				"vendor":    h.Vendor,
				"version":   h.Version,
				"evidence":  h.Evidence,
				"risk_note": h.RiskNote,
				"source":    "hmi",
			}
			evidenceBytes, _ := json.Marshal(evidence)
			f := models.Finding{
				IdentityID:  asset.IdentityID,
				AssetID:     asset.ID,
				Title:       title,
				Description: desc,
				Severity:    models.SeverityHigh,
				Category:    "ot",
				Protocol:    "hmi",
				Vendor:      h.Vendor,
				Evidence:    evidenceBytes,
			}
			saved, err := st.InsertFinding(r.Context(), f)
			if err != nil {
				log.Debug().Err(err).Str("title", title).Msg("hmi: skipped duplicate finding")
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

// HandleGetHMI handles GET /api/v1/assets/{asset_id}/hmi.
// Returns the stored HMI enrichment record or null if not found.
func HandleGetHMI(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceHMI {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}
