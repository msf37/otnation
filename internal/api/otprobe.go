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
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/otprobe"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleOTProbe handles POST /api/v1/assets/{asset_id}/ot-probe.
// Probes OT protocols on the asset IP, stores the result, and creates findings for each responding protocol.
func HandleOTProbe(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "OT probe is only supported for IP assets")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		result, err := otprobe.Probe(ctx, asset.Value)
		if err != nil && !errors.Is(err, otprobe.ErrNoResponse) {
			log.Error().Err(err).Str("ip", asset.Value).Msg("otprobe: probe failed")
			writeError(w, http.StatusBadGateway, "OT probe failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal OT probe result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceOTProbe,
			Data:    rawData,
		}

		saved, err := st.UpsertEnrichment(r.Context(), rec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment record: "+err.Error())
			return
		}

		// Create findings for responding OT protocols.
		var generatedFindings []models.Finding
		for _, probe := range result.Probes {
			if !probe.Responded {
				continue
			}

			desc := fmt.Sprintf("%s is exposed on %s:%d.", probe.Protocol, asset.Value, probe.Port)
			if len(probe.Fields) > 0 {
				desc += " Parsed fields: "
				first := true
				for k, v := range probe.Fields {
					if !first {
						desc += ", "
					}
					desc += k + "=" + v
					first = false
				}
			}
			if probe.Banner != "" {
				bannerSnip := probe.Banner
				if len(bannerSnip) > 200 {
					bannerSnip = bannerSnip[:200] + "..."
				}
				desc += " Banner: " + bannerSnip
			}

			evidence := map[string]interface{}{
				"port":     probe.Port,
				"protocol": probe.Protocol,
				"banner":   probe.Banner,
				"fields":   probe.Fields,
				"source":   "ot_probe",
			}
			evidenceBytes, _ := json.Marshal(evidence)

			finding := models.Finding{
				IdentityID:  asset.IdentityID,
				AssetID:     asset.ID,
				Title:       fmt.Sprintf("%s service exposed on %s:%d", probe.Protocol, asset.Value, probe.Port),
				Description: desc,
				Severity:    models.SeverityCritical,
				Category:    "industrial_protocol",
				Protocol:    probe.Protocol,
				Evidence:    evidenceBytes,
			}

			savedFinding, err := st.InsertFinding(r.Context(), finding)
			if err != nil {
				log.Debug().Err(err).Str("protocol", probe.Protocol).Msg("otprobe: skipped duplicate finding")
				continue
			}
			generatedFindings = append(generatedFindings, savedFinding)
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result":             saved,
			"findings_generated": len(generatedFindings),
			"findings":           generatedFindings,
		})
	}
}

// HandleGetOTProbe handles GET /api/v1/assets/{asset_id}/ot-probe.
// Returns the stored OT probe enrichment record.
func HandleGetOTProbe(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceOTProbe {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}
