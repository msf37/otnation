package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/config"
	"github.com/otnation/platform/internal/shodan"
	"github.com/otnation/platform/internal/store"
)

// HandleDeepScanShodan handles POST /api/v1/assets/{asset_id}/deep-scan.
// It calls Shodan synchronously and returns all gathered data in a single response.
func HandleDeepScanShodan(st *store.Store, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.Shodan.APIKey == "" {
			writeError(w, http.StatusServiceUnavailable, "Shodan API key not configured — set shodan.api_key in config.yaml")
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

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		client := shodan.New(cfg.Shodan.APIKey)
		result, err := client.DeepScan(ctx, st, assetID, asset.IdentityID)
		if err != nil {
			writeError(w, http.StatusBadGateway, "Shodan lookup failed: "+err.Error())
			return
		}

		writeJSON(w, http.StatusOK, result)
	}
}
