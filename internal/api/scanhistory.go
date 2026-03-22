package api

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/store"
)

func HandleGetAssetHistory(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetID, err := parseUUID(mux.Vars(r)["asset_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset id")
			return
		}
		history, err := st.ListScanHistory(r.Context(), assetID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeJSON(w, http.StatusOK, []interface{}{})
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get scan history")
			return
		}
		writeJSON(w, http.StatusOK, history)
	}
}
