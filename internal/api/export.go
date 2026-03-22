package api

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/reporting"
	"github.com/otnation/platform/internal/store"
)

// HandleExportAssetsJSON handles GET /api/v1/identities/{id}/export/assets.json
func HandleExportAssetsJSON(st *store.Store) http.HandlerFunc {
	rep := reporting.New(st)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}
		if _, err := st.GetIdentity(r.Context(), id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "identity not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get identity")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := rep.ExportAssetsJSON(r.Context(), id, w); err != nil {
			// Headers already sent; just log.
			return
		}
	}
}

// HandleExportAssetsCSV handles GET /api/v1/identities/{id}/export/assets.csv
func HandleExportAssetsCSV(st *store.Store) http.HandlerFunc {
	rep := reporting.New(st)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}
		if _, err := st.GetIdentity(r.Context(), id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "identity not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get identity")
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="assets.csv"`)
		if err := rep.ExportAssetsCSV(r.Context(), id, w); err != nil {
			return
		}
	}
}

// HandleExportFindingsJSON handles GET /api/v1/identities/{id}/export/findings.json
func HandleExportFindingsJSON(st *store.Store) http.HandlerFunc {
	rep := reporting.New(st)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}
		if _, err := st.GetIdentity(r.Context(), id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "identity not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get identity")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := rep.ExportFindingsJSON(r.Context(), id, w); err != nil {
			return
		}
	}
}

// HandleExportFindingsCSV handles GET /api/v1/identities/{id}/export/findings.csv
func HandleExportFindingsCSV(st *store.Store) http.HandlerFunc {
	rep := reporting.New(st)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}
		if _, err := st.GetIdentity(r.Context(), id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "identity not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get identity")
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="findings.csv"`)
		if err := rep.ExportFindingsCSV(r.Context(), id, w); err != nil {
			return
		}
	}
}
