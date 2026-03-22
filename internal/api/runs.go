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

// createRunRequest is the JSON body for POST /api/v1/identities/{id}/runs.
type createRunRequest struct {
	TriggeredBy string `json:"triggered_by"`
}

// runResponse wraps a Run with the initial jobs list.
type runResponse struct {
	Run  models.Run   `json:"run"`
	Jobs []models.Job `json:"jobs"`
}

// HandleCreateRun handles POST /api/v1/identities/{id}/runs.
// It creates a run and seeds it with initial discovery jobs for each seed.
func HandleCreateRun(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identityID, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}

		// Verify identity exists.
		if _, err := st.GetIdentity(r.Context(), identityID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "identity not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to verify identity")
			return
		}

		var req createRunRequest
		_ = json.NewDecoder(r.Body).Decode(&req) // body is optional
		triggeredBy := req.TriggeredBy
		if triggeredBy == "" {
			triggeredBy = "api"
		}

		run, err := st.CreateRun(r.Context(), identityID, triggeredBy)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create run")
			return
		}

		// Enqueue a single discovery_run job. The discovery engine loads
		// all seeds for the identity itself.
		payload, _ := json.Marshal(map[string]string{
			"run_id":      run.ID.String(),
			"identity_id": identityID.String(),
		})
		job, err := st.CreateJob(r.Context(), run.ID, models.JobTypeDiscoveryRun, payload)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create discovery job")
			return
		}
		jobs := []models.Job{job}

		writeJSON(w, http.StatusCreated, runResponse{Run: run, Jobs: jobs})
	}
}

// HandleListRuns handles GET /api/v1/identities/{id}/runs.
func HandleListRuns(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identityID, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}

		runs, err := st.ListRuns(r.Context(), identityID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list runs")
			return
		}
		writeJSON(w, http.StatusOK, runs)
	}
}

// HandleGetRun handles GET /api/v1/runs/{run_id}.
func HandleGetRun(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		runID, err := parseUUID(mux.Vars(r)["run_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid run id")
			return
		}

		run, err := st.GetRun(r.Context(), runID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "run not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get run")
			return
		}

		// Also fetch associated jobs.
		jobs, err := st.ListJobs(r.Context(), runID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list jobs for run")
			return
		}

		writeJSON(w, http.StatusOK, struct {
			Run  models.Run   `json:"run"`
			Jobs []models.Job `json:"jobs"`
		}{
			Run:  run,
			Jobs: jobs,
		})
	}
}

