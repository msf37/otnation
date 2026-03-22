package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/otnation/platform/internal/tlsscanner"
)

// HandleTLSScan handles POST /api/v1/assets/{asset_id}/tls-scan.
// Runs a TLS certificate + protocol scan synchronously and stores the result.
func HandleTLSScan(st *store.Store) http.HandlerFunc {
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
		if asset.Type != "domain" && asset.Type != "subdomain" {
			writeError(w, http.StatusBadRequest, "TLS scanning is only supported for domain assets")
			return
		}

		res := tlsscanner.Scan(r.Context(), asset.Value)

		// Marshal JSONB fields.
		sansJSON, _ := json.Marshal(res.SANs)
		issuesJSON, _ := json.Marshal(res.Issues)

		rec := models.TLSScanResult{
			AssetID:         assetID,
			IdentityID:      asset.IdentityID,
			ScannedAt:       time.Now().UTC(),
			CommonName:      res.CommonName,
			Issuer:          res.Issuer,
			SANs:            sansJSON,
			NotBefore:       res.NotBefore,
			NotAfter:        res.NotAfter,
			DaysUntilExpiry: res.DaysUntilExpiry,
			TLSVersion:      res.TLSVersion,
			CipherSuite:     res.CipherSuite,
			KeyAlgorithm:    res.KeyAlgorithm,
			KeySize:         res.KeySize,
			SignatureAlgo:   res.SignatureAlgo,
			Grade:           res.Grade,
			Issues:          issuesJSON,
			ErrorMsg:        res.ErrorMsg,
		}

		saved, err := st.UpsertTLSScanResult(r.Context(), rec)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save TLS scan result: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, saved)
	}
}

// HandleGetTLSScan handles GET /api/v1/assets/{asset_id}/tls-scan.
// Returns the stored TLS scan result for a domain asset.
func HandleGetTLSScan(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetID, err := parseUUID(mux.Vars(r)["asset_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset id")
			return
		}

		result, err := st.GetTLSScanResult(r.Context(), assetID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeJSON(w, http.StatusOK, nil)
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get TLS scan result")
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}
