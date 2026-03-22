package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// ---------------------------------------------------------------------------
// Identity handlers
// ---------------------------------------------------------------------------

// createIdentityRequest is the JSON body for POST /api/v1/identities.
type createIdentityRequest struct {
	Name    string          `json:"name"`
	OrgName string          `json:"org_name"`
	Notes   string          `json:"notes"`
	Sector  string          `json:"sector"`
	Tags    json.RawMessage `json:"tags"`
}

// updateIdentityRequest is the JSON body for PUT /api/v1/identities/{id}.
type updateIdentityRequest struct {
	Name    string          `json:"name"`
	OrgName string          `json:"org_name"`
	Notes   string          `json:"notes"`
	Sector  string          `json:"sector"`
	Tags    json.RawMessage `json:"tags"`
}

// HandleCreateIdentity handles POST /api/v1/identities.
func HandleCreateIdentity(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createIdentityRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Name == "" || req.OrgName == "" {
			writeError(w, http.StatusBadRequest, "name and org_name are required")
			return
		}

		tags := []byte(req.Tags)
		if len(tags) == 0 {
			tags = []byte("[]")
		}

		identity, err := st.CreateIdentity(r.Context(), req.Name, req.OrgName, req.Notes, req.Sector, tags)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create identity")
			return
		}
		writeJSON(w, http.StatusCreated, identity)
	}
}

// HandleListIdentities handles GET /api/v1/identities.
func HandleListIdentities(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identities, err := st.ListIdentities(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list identities")
			return
		}
		writeJSON(w, http.StatusOK, identities)
	}
}

// HandleGetIdentity handles GET /api/v1/identities/{id}.
func HandleGetIdentity(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}

		identity, err := st.GetIdentity(r.Context(), id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "identity not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get identity")
			return
		}
		writeJSON(w, http.StatusOK, identity)
	}
}

// HandleUpdateIdentity handles PUT /api/v1/identities/{id}.
func HandleUpdateIdentity(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}

		var req updateIdentityRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Name == "" || req.OrgName == "" {
			writeError(w, http.StatusBadRequest, "name and org_name are required")
			return
		}

		tags := []byte(req.Tags)
		if len(tags) == 0 {
			tags = []byte("[]")
		}

		identity, err := st.UpdateIdentity(r.Context(), id, req.Name, req.OrgName, req.Notes, req.Sector, tags)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "identity not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to update identity")
			return
		}
		writeJSON(w, http.StatusOK, identity)
	}
}

// HandleDeleteIdentity handles DELETE /api/v1/identities/{id}.
func HandleDeleteIdentity(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}

		if err := st.DeleteIdentity(r.Context(), id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "identity not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to delete identity")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// Seed handlers
// ---------------------------------------------------------------------------

// createSeedRequest is the JSON body for POST /api/v1/identities/{id}/seeds.
type createSeedRequest struct {
	Type  models.SeedType `json:"type"`
	Value string          `json:"value"`
}

// HandleCreateSeed handles POST /api/v1/identities/{id}/seeds.
func HandleCreateSeed(st *store.Store) http.HandlerFunc {
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

		var req createSeedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Value == "" {
			writeError(w, http.StatusBadRequest, "value is required")
			return
		}
		switch req.Type {
		case models.SeedTypeIP, models.SeedTypeCIDR, models.SeedTypeDomain:
			// valid
		default:
			writeError(w, http.StatusBadRequest, "type must be one of: ip, cidr, domain")
			return
		}

		seed, err := st.CreateSeed(r.Context(), identityID, req.Type, req.Value)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create seed")
			return
		}
		writeJSON(w, http.StatusCreated, seed)
	}
}

// HandleListSeeds handles GET /api/v1/identities/{id}/seeds.
func HandleListSeeds(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identityID, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}

		seeds, err := st.ListSeeds(r.Context(), identityID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list seeds")
			return
		}
		writeJSON(w, http.StatusOK, seeds)
	}
}
