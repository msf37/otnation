package api

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/store"
	"github.com/otnation/platform/internal/vulnnotes"
)

// HandleGetVulnNotes handles GET /api/v1/assets/{asset_id}/vuln-notes.
// Returns vulnerability notes and red-team tips for each open port on the asset.
func HandleGetVulnNotes(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetID, err := parseUUID(mux.Vars(r)["asset_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset id")
			return
		}

		// Verify asset exists.
		_, err = st.GetAsset(r.Context(), assetID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "asset not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get asset")
			return
		}

		// Get scan results to know which ports are open.
		scanResults, err := st.ListScanResults(r.Context(), assetID)
		if err != nil {
			scanResults = nil
		}

		type NoteResult struct {
			*vulnnotes.Note
			IsOpen bool `json:"is_open"`
		}

		var notes []NoteResult

		seen := make(map[int]bool)

		// First, include notes for open ports.
		for _, sr := range scanResults {
			if seen[sr.Port] {
				continue
			}
			seen[sr.Port] = true
			note := vulnnotes.GetNotes(sr.Port)
			if note != nil {
				notes = append(notes, NoteResult{Note: note, IsOpen: true})
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"asset_id": assetID,
			"notes":    notes,
			"count":    len(notes),
		})
	}
}
