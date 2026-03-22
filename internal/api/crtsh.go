package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/crtsh"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleCrtShLookup handles POST /api/v1/assets/{asset_id}/crtsh.
// Queries crt.sh for certificate transparency data for a domain/subdomain asset,
// saves the result as an enrichment record, and upserts discovered names as subdomain
// assets.
func HandleCrtShLookup(st *store.Store) http.HandlerFunc {
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

		if asset.Type != models.AssetTypeDomain && asset.Type != models.AssetTypeSubdomain {
			writeError(w, http.StatusBadRequest, "crt.sh lookup is only supported for domain and subdomain assets")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := crtsh.Search(ctx, asset.Value)
		if err != nil {
			if errors.Is(err, crtsh.ErrNoData) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"message":    "No certificates found in crt.sh for this domain",
					"names":      []string{},
					"count":      0,
					"new_assets": 0,
				})
				return
			}
			log.Error().Err(err).Str("domain", asset.Value).Msg("crtsh: lookup failed")
			writeError(w, http.StatusBadGateway, "crt.sh lookup failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal crt.sh result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceCrtSh,
			Data:    rawData,
		}

		_, err = st.UpsertEnrichment(r.Context(), rec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment record: "+err.Error())
			return
		}

		// Upsert each discovered name as a subdomain asset.
		newAssets := 0
		for _, name := range result.Names {
			if name == asset.Value {
				continue // skip the domain itself
			}
			subAsset := models.Asset{
				IdentityID: asset.IdentityID,
				Type:       models.AssetTypeSubdomain,
				Value:      name,
				Provenance: models.ProvenanceExternalEnrich,
			}
			if _, err := st.UpsertAsset(r.Context(), subAsset); err != nil {
				log.Warn().Err(err).Str("name", name).Msg("crtsh: failed to upsert subdomain asset")
			} else {
				newAssets++
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"names":      result.Names,
			"count":      len(result.Names),
			"new_assets": newAssets,
		})
	}
}

// HandleGetCrtSh handles GET /api/v1/assets/{asset_id}/crtsh.
// Returns the stored crt.sh enrichment record or null if not found.
func HandleGetCrtSh(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceCrtSh {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}
