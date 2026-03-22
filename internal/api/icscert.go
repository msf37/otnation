package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/icscert"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleICSCertSearch handles POST /api/v1/assets/{asset_id}/icscert.
// Searches CISA KEV for ICS advisories relevant to the asset's vendor/product.
// It derives the keyword from the Shodan enrichment data, the asset hostname,
// or a ?keyword= query parameter.
func HandleICSCertSearch(st *store.Store) http.HandlerFunc {
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

		// Determine keyword: query param > Shodan org/tags > asset reverse DNS.
		keyword := r.URL.Query().Get("keyword")
		if keyword == "" {
			keyword = derivedKeyword(r.Context(), st, assetID, asset)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		result, err := icscert.Search(ctx, keyword)
		if err != nil {
			if errors.Is(err, icscert.ErrNoAdvisories) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"result":  nil,
					"keyword": keyword,
					"message": "No ICS advisories found for this keyword",
				})
				return
			}
			log.Error().Err(err).Str("keyword", keyword).Msg("icscert: search failed")
			writeError(w, http.StatusInternalServerError, "ICS-CERT search failed: "+err.Error())
			return
		}

		rawData, err := json.Marshal(result)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal result")
			return
		}

		rec := models.EnrichmentRecord{
			AssetID: assetID,
			Source:  models.EnrichmentSourceICSCert,
			Data:    rawData,
		}
		if _, err = st.UpsertEnrichment(r.Context(), rec); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save enrichment: "+err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"result":  result,
			"keyword": keyword,
		})
	}
}

// HandleGetICSCert handles GET /api/v1/assets/{asset_id}/icscert.
// Returns the stored ICS-CERT enrichment record or null if not found.
func HandleGetICSCert(st *store.Store) http.HandlerFunc {
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
			if rec.Source == models.EnrichmentSourceICSCert {
				writeJSON(w, http.StatusOK, rec)
				return
			}
		}

		writeJSON(w, http.StatusOK, nil)
	}
}

// derivedKeyword extracts a vendor/product keyword from Shodan enrichment data
// or the asset's hostname/reverse DNS.
func derivedKeyword(ctx context.Context, st *store.Store, assetID interface{ String() string }, asset models.Asset) string {
	// Try Shodan enrichment for org/isp/device info.
	records, err := st.GetEnrichment(ctx, asset.ID)
	if err == nil {
		for _, rec := range records {
			if rec.Source == models.EnrichmentSourceShodan {
				var data map[string]interface{}
				if json.Unmarshal(rec.Data, &data) == nil {
					// Look for org, isp, product fields.
					for _, field := range []string{"org", "isp", "os", "product"} {
						if v, ok := data[field].(string); ok && v != "" {
							// Extract first meaningful word.
							word := firstMeaningfulWord(v)
							if word != "" {
								return word
							}
						}
					}
				}
				break
			}
		}
	}

	// Fall back to ASN org.
	if asset.ASNOrg != "" {
		word := firstMeaningfulWord(asset.ASNOrg)
		if word != "" {
			return word
		}
	}

	// Fall back to reverse DNS.
	if asset.ReverseDNS != "" {
		return asset.ReverseDNS
	}

	// Generic OT search.
	return "scada"
}

// firstMeaningfulWord returns the first word longer than 3 chars that isn't a stop word.
func firstMeaningfulWord(s string) string {
	stopWords := map[string]bool{
		"the": true, "inc": true, "ltd": true, "llc": true, "corp": true,
		"and": true, "for": true, "com": true, "net": true, "org": true,
	}
	words := strings.Fields(s)
	for _, w := range words {
		clean := strings.ToLower(strings.Trim(w, ".,;:\"'()-"))
		if len(clean) > 3 && !stopWords[clean] {
			return clean
		}
	}
	return ""
}
