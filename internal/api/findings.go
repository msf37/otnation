package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

// HandleListIdentityFindings handles GET /api/v1/identities/{id}/findings.
// Query params: severity, vendor, protocol, page, limit.
func HandleListIdentityFindings(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identityID, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}

		q := r.URL.Query()
		page, _ := strconv.Atoi(q.Get("page"))
		limit, _ := strconv.Atoi(q.Get("limit"))
		if page <= 0 {
			page = 1
		}
		if limit <= 0 {
			limit = 50
		}

		findings, err := st.ListFindings(r.Context(), store.FindingFilters{
			IdentityID: &identityID,
			Severity:   q.Get("severity"),
			Vendor:     q.Get("vendor"),
			Protocol:   q.Get("protocol"),
			Page:       page,
			Limit:      limit,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list findings")
			return
		}
		writeJSON(w, http.StatusOK, findings)
	}
}

// HandleGetFinding handles GET /api/v1/findings/{finding_id}.
func HandleGetFinding(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		findingID, err := parseUUID(mux.Vars(r)["finding_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid finding id")
			return
		}

		finding, err := st.GetFinding(r.Context(), findingID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "finding not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get finding")
			return
		}
		writeJSON(w, http.StatusOK, finding)
	}
}

// patchFindingRequest is the body for PATCH /api/v1/findings/{finding_id}.
type patchFindingRequest struct {
	Description string                `json:"description"`
	Severity    models.SeverityLevel  `json:"severity"`
	Evidence    json.RawMessage       `json:"evidence"`
}

// HandlePatchFinding handles PATCH /api/v1/findings/{finding_id}.
func HandlePatchFinding(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		findingID, err := parseUUID(mux.Vars(r)["finding_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid finding id")
			return
		}

		// Load the existing finding first so we can merge defaults.
		existing, err := st.GetFinding(r.Context(), findingID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "finding not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get finding")
			return
		}

		var req patchFindingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Merge: only update fields that were supplied.
		description := existing.Description
		if req.Description != "" {
			description = req.Description
		}
		severity := existing.Severity
		if req.Severity != "" {
			switch req.Severity {
			case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium,
				models.SeverityLow, models.SeverityInformational:
				severity = req.Severity
			default:
				writeError(w, http.StatusBadRequest, "invalid severity value")
				return
			}
		}
		evidence := existing.Evidence
		if len(req.Evidence) > 0 {
			evidence = []byte(req.Evidence)
		}

		updated, err := st.UpdateFinding(r.Context(), findingID, description, severity, evidence)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "finding not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to update finding")
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}
