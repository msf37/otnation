package api

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/store"
)

// HandleGetIdentityStats handles GET /api/v1/identities/{id}/stats.
func HandleGetIdentityStats(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}

		// Verify identity exists.
		if _, err := st.GetIdentity(r.Context(), id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "identity not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get identity")
			return
		}

		stats, err := st.GetIdentityStats(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to get stats")
			return
		}

		writeJSON(w, http.StatusOK, stats)
	}
}
