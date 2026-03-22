package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	censysclient "github.com/otnation/platform/internal/censys"
	"github.com/otnation/platform/internal/config"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

func HandleFetchCensys(st *store.Store, cfg *config.Config) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "Censys lookup requires an IP asset")
			return
		}

		client := censysclient.NewClient(cfg.Censys.APIID, cfg.Censys.APISecret)
		hostData, err := client.FetchHost(r.Context(), asset.Value)
		if err != nil {
			if errors.Is(err, censysclient.ErrNotFound) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"result": nil, "message": "Host not found in Censys",
				})
				return
			}
			log.Error().Err(err).Str("target", asset.Value).Msg("censys: fetch failed")
			writeError(w, http.StatusInternalServerError, "Censys fetch failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(hostData)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal Censys result")
			return
		}
		rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceCensys, Data: rawData}
		if _, err = st.UpsertEnrichment(r.Context(), rec); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment: "+err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result": hostData,
		})
	}
}

func HandleGetCensys(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceCensys {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}
		writeJSON(w, http.StatusOK, nil)
	}
}
