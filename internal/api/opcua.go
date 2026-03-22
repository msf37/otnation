package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/opcua"
	"github.com/otnation/platform/internal/store"
	"github.com/otnation/platform/internal/threatintel"
	"github.com/rs/zerolog/log"
)

func HandleOPCUAScan(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "OPC-UA scan requires an IP asset")
			return
		}

		result, err := opcua.Scan(asset.Value)
		if err != nil {
			if errors.Is(err, opcua.ErrNoResponse) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"result": nil, "message": "No OPC-UA response from target", "findings": []interface{}{},
				})
				return
			}
			log.Error().Err(err).Str("target", asset.Value).Msg("opcua: scan failed")
			writeError(w, http.StatusInternalServerError, "OPC-UA scan failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal scan result")
			return
		}
		rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceOPCUA, Data: rawData}
		if _, err = st.UpsertEnrichment(r.Context(), rec); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment: "+err.Error())
			return
		}

		var generatedFindings []models.Finding
		if result.Responded {
			ttps := threatintel.LookupTTPs("opcua", "ot")
			ttpsBytes, _ := json.Marshal(ttps)
			evidenceBytes, _ := json.Marshal(map[string]interface{}{
				"port": 4840, "server_uri": result.ServerURI,
				"endpoints": result.Endpoints, "raw_banner": result.RawBanner,
			})

			f := models.Finding{
				IdentityID: asset.IdentityID, AssetID: asset.ID,
				Title:       "OPC-UA Server Exposed",
				Description: "OPC-UA server detected at " + asset.Value + " on port 4840. OPC-UA is a machine-to-machine communication protocol used across industrial automation systems.",
				Severity:    models.SeverityMedium, Category: "ot", Protocol: "opcua", Vendor: "OPC Foundation",
				Evidence: evidenceBytes, AttackTTPs: ttpsBytes,
			}
			if saved, err := st.InsertFinding(r.Context(), f); err != nil {
				log.Debug().Err(err).Msg("opcua: skipped duplicate finding")
			} else {
				generatedFindings = append(generatedFindings, saved)
			}

			// Check for endpoints with no security
			for _, ep := range result.Endpoints {
				if ep.SecurityMode == "None" {
					f2 := models.Finding{
						IdentityID: asset.IdentityID, AssetID: asset.ID,
						Title:       "OPC-UA No Security",
						Description: "OPC-UA endpoint detected at " + ep.URL + " with SecurityMode=None. This allows unauthenticated and unencrypted access to the OPC-UA server.",
						Severity:    models.SeverityHigh, Category: "ot", Protocol: "opcua", Vendor: "OPC Foundation",
						Evidence: evidenceBytes, AttackTTPs: ttpsBytes,
					}
					if saved, err := st.InsertFinding(r.Context(), f2); err != nil {
						log.Debug().Err(err).Msg("opcua: skipped no-security finding")
					} else {
						generatedFindings = append(generatedFindings, saved)
					}
					break
				}
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result": result, "findings_generated": len(generatedFindings), "findings": generatedFindings,
		})
	}
}

func HandleGetOPCUA(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceOPCUA {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}
		writeJSON(w, http.StatusOK, nil)
	}
}
