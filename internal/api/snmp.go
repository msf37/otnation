package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/snmp"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleSNMPEnum handles POST /api/v1/assets/{asset_id}/snmp.
// Runs SNMP community string enumeration on the asset IP and stores the result.
func HandleSNMPEnum(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "SNMP enumeration is only supported for IP assets")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		result, err := snmp.Enumerate(ctx, asset.Value)
		if err != nil {
			if errors.Is(err, snmp.ErrNoData) {
				writeJSON(w, http.StatusOK, map[string]string{"message": "No SNMP community string responded"})
				return
			}
			log.Error().Err(err).Str("ip", asset.Value).Msg("snmp: enumeration failed")
			writeError(w, http.StatusBadGateway, "SNMP enumeration failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal SNMP result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceSNMP,
			Data:    rawData,
		}

		saved, err := st.UpsertEnrichment(r.Context(), rec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment record: "+err.Error())
			return
		}

		writeJSON(w, http.StatusOK, saved)
	}
}

// HandleGetSNMP handles GET /api/v1/assets/{asset_id}/snmp.
// Returns the stored SNMP enrichment record for the asset.
func HandleGetSNMP(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceSNMP {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}
