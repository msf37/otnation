package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/bgp"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleBGPLookup handles POST /api/v1/assets/{asset_id}/bgp.
// Looks up BGP/ASN data for the asset IP and stores it as an enrichment record.
func HandleBGPLookup(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "BGP lookup is only supported for IP assets")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		result, err := bgp.Lookup(ctx, asset.Value)
		if err != nil {
			if errors.Is(err, bgp.ErrNoData) {
				writeJSON(w, http.StatusOK, map[string]string{"message": "BGPView has no data for this IP"})
				return
			}
			log.Error().Err(err).Str("ip", asset.Value).Msg("bgp: lookup failed")
			writeError(w, http.StatusBadGateway, "BGP lookup failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal BGP result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceBGP,
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

// HandleGetBGP handles GET /api/v1/assets/{asset_id}/bgp.
// Returns the stored BGP enrichment record.
func HandleGetBGP(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceBGP {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}
