package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/iec61850"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleIEC61850Scan handles POST /api/v1/assets/{asset_id}/iec61850.
// Runs an IEC 61850 MMS scan against the asset IP, stores the result as an
// enrichment record, and creates a finding if an IED is detected.
func HandleIEC61850Scan(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "IEC 61850 scan requires an IP asset")
			return
		}

		result, err := iec61850.Scan(asset.Value)
		if err != nil {
			if errors.Is(err, iec61850.ErrNoResponse) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"result":   nil,
					"message":  "No IEC 61850/MMS response from target",
					"findings": []interface{}{},
				})
				return
			}
			log.Error().Err(err).Str("target", asset.Value).Msg("iec61850: scan failed")
			writeError(w, http.StatusInternalServerError, "IEC 61850 scan failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal scan result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceIEC61850,
			Data:    rawData,
		}
		if _, err = st.UpsertEnrichment(r.Context(), rec); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment: "+err.Error())
			return
		}

		var generatedFindings []models.Finding
		if result.Responded && result.DeviceType == "IEC 61850 MMS" {
			desc := "An IEC 61850 MMS Intelligent Electronic Device (IED) was detected at " + asset.Value + " on port 102."
			if len(result.LogicalDevices) > 0 {
				desc += " Logical device names found: " + joinStrings(result.LogicalDevices)
			}
			evidence := map[string]interface{}{
				"port":            102,
				"device_type":     result.DeviceType,
				"logical_devices": result.LogicalDevices,
				"raw_banner":      result.RawBanner,
				"source":          "iec61850",
			}
			evidenceBytes, _ := json.Marshal(evidence)
			f := models.Finding{
				IdentityID:  asset.IdentityID,
				AssetID:     asset.ID,
				Title:       "IEC 61850 MMS IED Exposed",
				Description: desc,
				Severity:    models.SeverityCritical,
				Category:    "ot",
				Protocol:    "iec61850",
				Vendor:      "IEC",
				Evidence:    evidenceBytes,
			}
			saved, err := st.InsertFinding(r.Context(), f)
			if err != nil {
				log.Debug().Err(err).Msg("iec61850: skipped duplicate finding")
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

// HandleGetIEC61850 handles GET /api/v1/assets/{asset_id}/iec61850.
// Returns the stored IEC 61850 enrichment record or null if not found.
func HandleGetIEC61850(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceIEC61850 {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}

func joinStrings(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
