package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

// HandleGetNERCCIP handles GET /api/v1/assets/{asset_id}/nerc-cip.
// Returns the NERC CIP classification for the asset.
func HandleGetNERCCIP(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetID, err := parseUUID(mux.Vars(r)["asset_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset id")
			return
		}

		// Verify the asset exists.
		if _, err := st.GetAsset(r.Context(), assetID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "asset not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get asset")
			return
		}

		classification, err := st.GetAssetNERCCIP(r.Context(), assetID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeJSON(w, http.StatusOK, models.NERCCIPClassification{})
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get NERC CIP classification")
			return
		}

		writeJSON(w, http.StatusOK, classification)
	}
}

// HandleSetNERCCIP handles PUT /api/v1/assets/{asset_id}/nerc-cip.
// Sets the NERC CIP classification for the asset (full replacement).
func HandleSetNERCCIP(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetID, err := parseUUID(mux.Vars(r)["asset_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset id")
			return
		}

		// Verify the asset exists.
		if _, err := st.GetAsset(r.Context(), assetID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "asset not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get asset")
			return
		}

		var classification models.NERCCIPClassification
		if err := json.NewDecoder(r.Body).Decode(&classification); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		if err := st.UpdateAssetNERCCIP(r.Context(), assetID, classification); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update NERC CIP classification")
			return
		}

		writeJSON(w, http.StatusOK, classification)
	}
}
