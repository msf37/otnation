package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/otnation/platform/internal/threatintel"
	"github.com/rs/zerolog/log"
)

func HandleTestDefaultCreds(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "default credentials test requires an IP asset")
			return
		}

		report, err := threatintel.TestDefaultCreds(r.Context(), asset.Value)
		if err != nil {
			if errors.Is(err, threatintel.ErrNoResponse) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"result": nil, "message": "Target not reachable via HTTP/HTTPS", "findings": []interface{}{},
				})
				return
			}
			log.Error().Err(err).Str("target", asset.Value).Msg("defcreds: scan failed")
			writeError(w, http.StatusInternalServerError, "default credentials test failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(report)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal report")
			return
		}
		rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceDefaultCreds, Data: rawData}
		if _, err = st.UpsertEnrichment(r.Context(), rec); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment: "+err.Error())
			return
		}

		var generatedFindings []models.Finding
		if report.Found {
			ttps := threatintel.LookupTTPs("default_creds", "credential")
			ttpsBytes, _ := json.Marshal(ttps)

			// Collect successful credentials
			var successCreds []map[string]interface{}
			for _, cr := range report.Results {
				if cr.Success {
					successCreds = append(successCreds, map[string]interface{}{
						"url": cr.URL, "username": cr.Username,
						"password": cr.Password, "http_status": cr.Status,
					})
				}
			}
			evidenceBytes, _ := json.Marshal(map[string]interface{}{
				"target": asset.Value, "successful_creds": successCreds,
			})

			f := models.Finding{
				IdentityID: asset.IdentityID, AssetID: asset.ID,
				Title:       "Default Credentials Accepted",
				Description: "Default credentials were accepted on " + asset.Value + ". This provides unauthorized access to the device management interface.",
				Severity:    models.SeverityCritical, Category: "authentication", Protocol: "http", Vendor: "",
				Evidence: evidenceBytes, AttackTTPs: ttpsBytes,
			}
			if saved, err := st.InsertFinding(r.Context(), f); err != nil {
				log.Debug().Err(err).Msg("defcreds: skipped duplicate finding")
			} else {
				generatedFindings = append(generatedFindings, saved)
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result": report, "findings_generated": len(generatedFindings), "findings": generatedFindings,
		})
	}
}

func HandleGetDefaultCreds(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceDefaultCreds {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}
		writeJSON(w, http.StatusOK, nil)
	}
}
