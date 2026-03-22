package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/config"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/securitytrails"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleSecurityTrailsEnrich handles POST /api/v1/assets/{asset_id}/securitytrails.
// Calls SecurityTrails to fetch domain intelligence and stores it as an enrichment record.
func HandleSecurityTrailsEnrich(st *store.Store, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.SecurityTrails.APIKey == "" {
			writeError(w, http.StatusServiceUnavailable, "SecurityTrails API key not configured — set security_trails.api_key in config.yaml")
			return
		}

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

		if asset.Type != models.AssetTypeDomain && asset.Type != models.AssetTypeSubdomain {
			writeError(w, http.StatusBadRequest, "SecurityTrails enrichment is only supported for domain and subdomain assets")
			return
		}

		// Use an independent context with a 5-minute timeout so the request
		// is not cancelled if the client disconnects mid-flight.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		client := securitytrails.New(cfg.SecurityTrails.APIKey)
		result, err := client.Enrich(ctx, asset.Value)
		if err != nil {
			if errors.Is(err, securitytrails.ErrNoData) {
				writeJSON(w, http.StatusOK, map[string]string{"message": "SecurityTrails has no data for this domain"})
				return
			}
			log.Error().Err(err).Str("domain", asset.Value).Msg("securitytrails: enrich failed")
			writeError(w, http.StatusBadGateway, "SecurityTrails lookup failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal SecurityTrails result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceSecurityTrails,
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

// HandleGetSecurityTrailsEnrich handles GET /api/v1/assets/{asset_id}/securitytrails.
// Returns the stored SecurityTrails enrichment record for a domain asset, or null.
func HandleGetSecurityTrailsEnrich(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceSecurityTrails {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}
