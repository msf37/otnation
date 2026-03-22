package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/enipdeep"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/otnation/platform/internal/threatintel"
	"github.com/rs/zerolog/log"
)

func HandleEtherNetIPDeepScan(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "EtherNet/IP deep scan requires an IP asset")
			return
		}

		result, err := enipdeep.Scan(asset.Value)
		if err != nil {
			if errors.Is(err, enipdeep.ErrNoResponse) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"result": nil, "message": "No EtherNet/IP response from target", "findings": []interface{}{},
				})
				return
			}
			log.Error().Err(err).Str("target", asset.Value).Msg("enipdeep: scan failed")
			writeError(w, http.StatusInternalServerError, "EtherNet/IP deep scan failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal scan result")
			return
		}
		rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceEtherNetIPDeep, Data: rawData}
		if _, err = st.UpsertEnrichment(r.Context(), rec); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment: "+err.Error())
			return
		}

		var generatedFindings []models.Finding
		if result.Responded && len(result.Tags) > 0 {
			ttps := threatintel.LookupTTPs("enip", "ot")
			ttpsBytes, _ := json.Marshal(ttps)
			evidenceBytes, _ := json.Marshal(map[string]interface{}{
				"port": 44818, "product_name": result.ProductName,
				"vendor_id": result.VendorID, "device_type": result.DeviceType,
				"tags": result.Tags, "raw_banner": result.RawBanner,
			})
			f := models.Finding{
				IdentityID: asset.IdentityID, AssetID: asset.ID,
				Title:       "EtherNet/IP CIP Deep Exposure",
				Description: "EtherNet/IP CIP tags and identity information was enumerated from " + asset.Value + " on port 44818. CIP tag access enables PLC logic reading and potential write operations.",
				Severity:    models.SeverityHigh, Category: "ot", Protocol: "enip", Vendor: "ODVA",
				Evidence: evidenceBytes, AttackTTPs: ttpsBytes,
			}
			if saved, err := st.InsertFinding(r.Context(), f); err != nil {
				log.Debug().Err(err).Msg("enipdeep: skipped duplicate finding")
			} else {
				generatedFindings = append(generatedFindings, saved)
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result": result, "findings_generated": len(generatedFindings), "findings": generatedFindings,
		})
	}
}

func HandleGetEtherNetIPDeep(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceEtherNetIPDeep {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}
		writeJSON(w, http.StatusOK, nil)
	}
}
