package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/profinet"
	"github.com/otnation/platform/internal/store"
	"github.com/otnation/platform/internal/threatintel"
	"github.com/rs/zerolog/log"
)

func HandleProfinetScan(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "Profinet scan requires an IP asset")
			return
		}

		result, err := profinet.Scan(asset.Value)
		if err != nil {
			if errors.Is(err, profinet.ErrNoResponse) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"result": nil, "message": "No Profinet DCP response from target", "findings": []interface{}{},
				})
				return
			}
			log.Error().Err(err).Str("target", asset.Value).Msg("profinet: scan failed")
			writeError(w, http.StatusInternalServerError, "Profinet scan failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal scan result")
			return
		}
		rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceProfinet, Data: rawData}
		if _, err = st.UpsertEnrichment(r.Context(), rec); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment: "+err.Error())
			return
		}

		var generatedFindings []models.Finding
		if result.Responded {
			ttps := threatintel.LookupTTPs("profinet", "ot")
			ttpsBytes, _ := json.Marshal(ttps)
			evidenceBytes, _ := json.Marshal(map[string]interface{}{
				"station_name": result.StationName, "vendor_id": result.VendorID, "raw_banner": result.RawBanner,
			})
			desc := "Profinet DCP device detected at " + asset.Value + " port 34964 (UDP)."
			if result.StationName != "" {
				desc += " Station name: " + result.StationName + "."
			}
			f := models.Finding{
				IdentityID: asset.IdentityID, AssetID: asset.ID,
				Title:       "Profinet DCP Device Exposed",
				Description: desc,
				Severity:    models.SeverityHigh, Category: "ot", Protocol: "profinet", Vendor: "Siemens/PROFIBUS",
				Evidence: evidenceBytes, AttackTTPs: ttpsBytes,
			}
			if saved, err := st.InsertFinding(r.Context(), f); err != nil {
				log.Debug().Err(err).Msg("profinet: skipped duplicate finding")
			} else {
				generatedFindings = append(generatedFindings, saved)
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result": result, "findings_generated": len(generatedFindings), "findings": generatedFindings,
		})
	}
}

func HandleGetProfinet(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceProfinet {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}
		writeJSON(w, http.StatusOK, nil)
	}
}
