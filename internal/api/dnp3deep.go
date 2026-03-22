package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/dnp3deep"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/otnation/platform/internal/threatintel"
	"github.com/rs/zerolog/log"
)

func HandleDNP3DeepScan(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "DNP3 deep scan requires an IP asset")
			return
		}

		result, err := dnp3deep.Scan(asset.Value)
		if err != nil {
			if errors.Is(err, dnp3deep.ErrNoResponse) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"result": nil, "message": "No DNP3 response from target", "findings": []interface{}{},
				})
				return
			}
			log.Error().Err(err).Str("target", asset.Value).Msg("dnp3deep: scan failed")
			writeError(w, http.StatusInternalServerError, "DNP3 deep scan failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal scan result")
			return
		}
		rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceDNP3Deep, Data: rawData}
		if _, err = st.UpsertEnrichment(r.Context(), rec); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment: "+err.Error())
			return
		}

		var generatedFindings []models.Finding
		if result.Responded {
			ttps := threatintel.LookupTTPs("dnp3", "ot")
			ttpsBytes, _ := json.Marshal(ttps)
			evidenceBytes, _ := json.Marshal(map[string]interface{}{
				"port": 20000, "responded": result.Responded,
				"data_points": result.DataPoints, "raw_banner": result.RawBanner,
			})
			f := models.Finding{
				IdentityID: asset.IdentityID, AssetID: asset.ID,
				Title:       "DNP3 Data Point Exposure",
				Description: "DNP3 protocol responded at " + asset.Value + " on port 20000. DNP3 is used in substations and water treatment facilities; unauthenticated access enables process data theft and command injection.",
				Severity:    models.SeverityCritical, Category: "ot", Protocol: "dnp3", Vendor: "IEEE",
				Evidence: evidenceBytes, AttackTTPs: ttpsBytes,
			}
			if saved, err := st.InsertFinding(r.Context(), f); err != nil {
				log.Debug().Err(err).Msg("dnp3deep: skipped duplicate finding")
			} else {
				generatedFindings = append(generatedFindings, saved)
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result": result, "findings_generated": len(generatedFindings), "findings": generatedFindings,
		})
	}
}

func HandleGetDNP3Deep(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceDNP3Deep {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}
		writeJSON(w, http.StatusOK, nil)
	}
}
