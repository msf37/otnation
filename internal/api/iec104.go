package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/iec104"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/otnation/platform/internal/threatintel"
	"github.com/rs/zerolog/log"
)

func HandleIEC104Scan(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "IEC 104 scan requires an IP asset")
			return
		}

		result, err := iec104.Scan(asset.Value)
		if err != nil {
			if errors.Is(err, iec104.ErrNoResponse) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"result": nil, "message": "No IEC 60870-5-104 response from target", "findings": []interface{}{},
				})
				return
			}
			log.Error().Err(err).Str("target", asset.Value).Msg("iec104: scan failed")
			writeError(w, http.StatusInternalServerError, "IEC 104 scan failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal scan result")
			return
		}
		rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceIEC104, Data: rawData}
		if _, err = st.UpsertEnrichment(r.Context(), rec); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment: "+err.Error())
			return
		}

		var generatedFindings []models.Finding
		if result.Responded {
			ttps := threatintel.LookupTTPs("iec104", "ot")
			ttpsBytes, _ := json.Marshal(ttps)

			desc := "IEC 60870-5-104 service detected at " + asset.Value + " port 2404. This is the primary SCADA protocol for electricity grid remote terminal units and substations."
			if len(result.DataObjects) > 0 {
				desc += " Data objects are being actively streamed — process values are readable."
			}
			evidence := map[string]interface{}{
				"port": 2404, "device_type": result.DeviceType,
				"data_objects": result.DataObjects, "raw_banner": result.RawBanner, "source": "iec104",
			}
			evidenceBytes, _ := json.Marshal(evidence)
			f := models.Finding{
				IdentityID: asset.IdentityID, AssetID: asset.ID,
				Title: "IEC 60870-5-104 Service Exposed", Description: desc,
				Severity: models.SeverityCritical, Category: "ot", Protocol: "iec104", Vendor: "IEC",
				Evidence: evidenceBytes, AttackTTPs: ttpsBytes,
			}
			if saved, err := st.InsertFinding(r.Context(), f); err != nil {
				log.Debug().Err(err).Msg("iec104: skipped duplicate finding")
			} else {
				generatedFindings = append(generatedFindings, saved)
			}

			// IEC 62351 absence finding
			f2 := models.Finding{
				IdentityID: asset.IdentityID, AssetID: asset.ID,
				Title:       "IEC 62351 Security Not Implemented",
				Description: "IEC 60870-5-104 was detected at " + asset.Value + " without TLS-based IEC 62351 security. Attackers can intercept and inject SCADA control commands in plaintext.",
				Severity:    models.SeverityHigh, Category: "ot", Protocol: "iec104", Vendor: "IEC",
				Evidence: evidenceBytes, AttackTTPs: ttpsBytes,
			}
			if saved, err := st.InsertFinding(r.Context(), f2); err != nil {
				log.Debug().Err(err).Msg("iec104: skipped iec62351 finding")
			} else {
				generatedFindings = append(generatedFindings, saved)
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result": result, "findings_generated": len(generatedFindings), "findings": generatedFindings,
		})
	}
}

func HandleGetIEC104(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceIEC104 {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}
		writeJSON(w, http.StatusOK, nil)
	}
}
