package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/ipwhois"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleIPWhois handles POST /api/v1/assets/{asset_id}/ip-whois.
// Looks up IP WHOIS / geolocation data and stores it as an enrichment record.
func HandleIPWhois(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "IP WHOIS lookup is only supported for IP assets")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		result, err := ipwhois.Lookup(ctx, asset.Value)
		if err != nil {
			if errors.Is(err, ipwhois.ErrNoData) {
				writeJSON(w, http.StatusOK, map[string]string{"message": "ipwhois.app has no data for this IP"})
				return
			}
			log.Error().Err(err).Str("ip", asset.Value).Msg("ipwhois: lookup failed")
			writeError(w, http.StatusBadGateway, "IP WHOIS lookup failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal WHOIS result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceIPWhois,
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

// HandleGetIPWhois handles GET /api/v1/assets/{asset_id}/ip-whois.
// Returns the stored IP WHOIS enrichment record.
func HandleGetIPWhois(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceIPWhois {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}
