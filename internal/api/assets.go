package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/dns"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

// assetsResponse wraps the list result with pagination metadata.
type assetsResponse struct {
	Total         int64              `json:"total"`
	Page          int                `json:"page"`
	Limit         int                `json:"limit"`
	Assets        interface{}        `json:"assets"`
	FindingCounts map[string]int     `json:"finding_counts,omitempty"`
	DNSLinks      []dnsLink          `json:"dns_links,omitempty"`
}

// dnsLink represents a resolved IP address belonging to a domain asset,
// used to draw edges between domain and IP nodes in the graph view.
type dnsLink struct {
	DomainAssetID string `json:"domain_asset_id"`
	IP            string `json:"ip"`
}

// HandleListAssets handles GET /api/v1/identities/{id}/assets.
// Query params: type, country, asn, page, limit, graph (1 = include graph extras).
func HandleListAssets(st *store.Store) http.HandlerFunc {
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

		f := store.AssetFilters{
			IdentityID: &identityID,
			Type:       q.Get("type"),
			Country:    q.Get("country"),
			Page:       page,
			Limit:      limit,
		}

		if asnStr := q.Get("asn"); asnStr != "" {
			asn, err := strconv.ParseInt(asnStr, 10, 64)
			if err != nil {
				writeError(w, http.StatusBadRequest, "asn must be an integer")
				return
			}
			f.ASN = &asn
		}

		assets, err := st.ListAssets(r.Context(), f)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list assets")
			return
		}

		// Count for pagination.
		countFilters := f
		countFilters.Page = 0
		countFilters.Limit = 0
		total, err := st.CountAssets(r.Context(), countFilters)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to count assets")
			return
		}

		resp := assetsResponse{
			Total:  total,
			Page:   page,
			Limit:  limit,
			Assets: assets,
		}

		// Graph extras: finding counts and DNS links.
		if q.Get("graph") == "1" {
			findingCounts, err := st.GetAssetFindingCounts(r.Context(), identityID)
			if err == nil {
				resp.FindingCounts = findingCounts
			}

			dnsRecords, err := st.ListDNSRecordsByIdentity(r.Context(), identityID)
			if err == nil {
				seen := make(map[string]bool)
				for _, rec := range dnsRecords {
					key := rec.AssetID.String() + ":" + rec.Value
					if !seen[key] && rec.Value != "" {
						resp.DNSLinks = append(resp.DNSLinks, dnsLink{
							DomainAssetID: rec.AssetID.String(),
							IP:            rec.Value,
						})
						seen[key] = true
					}
				}
			}
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// HandleGetAsset handles GET /api/v1/assets/{asset_id}.
func HandleGetAsset(st *store.Store) http.HandlerFunc {
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
		writeJSON(w, http.StatusOK, asset)
	}
}

// HandleGetAssetScanResults handles GET /api/v1/assets/{asset_id}/scan-results.
func HandleGetAssetScanResults(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetID, err := parseUUID(mux.Vars(r)["asset_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset id")
			return
		}

		results, err := st.ListScanResults(r.Context(), assetID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list scan results")
			return
		}
		writeJSON(w, http.StatusOK, results)
	}
}

// HandleGetAssetFindings handles GET /api/v1/assets/{asset_id}/findings.
func HandleGetAssetFindings(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetID, err := parseUUID(mux.Vars(r)["asset_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset id")
			return
		}

		findings, err := st.ListFindings(r.Context(), store.FindingFilters{
			AssetID: &assetID,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list findings")
			return
		}
		writeJSON(w, http.StatusOK, findings)
	}
}

// HandleGetAssetEnrichment handles GET /api/v1/assets/{asset_id}/enrichment.
func HandleGetAssetEnrichment(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetID, err := parseUUID(mux.Vars(r)["asset_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset id")
			return
		}
		records, err := st.GetEnrichment(r.Context(), assetID)
		if err != nil {
			writeJSON(w, http.StatusOK, []interface{}{})
			return
		}
		writeJSON(w, http.StatusOK, records)
	}
}

// HandleGetAssetDNSRecords handles GET /api/v1/assets/{asset_id}/dns-records.
func HandleGetAssetDNSRecords(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetID, err := parseUUID(mux.Vars(r)["asset_id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid asset id")
			return
		}
		records, err := st.ListDNSRecords(r.Context(), assetID)
		if err != nil {
			writeJSON(w, http.StatusOK, []interface{}{})
			return
		}
		writeJSON(w, http.StatusOK, records)
	}
}

// HandleGetAssetSubdomains handles GET /api/v1/assets/{asset_id}/subdomains.
// Returns all subdomain assets that are children of the given domain asset.
func HandleGetAssetSubdomains(st *store.Store) http.HandlerFunc {
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

		subs, err := st.ListSubdomainsByParent(r.Context(), asset.IdentityID, asset.Value)
		if err != nil {
			writeJSON(w, http.StatusOK, []interface{}{})
			return
		}
		writeJSON(w, http.StatusOK, subs)
	}
}

// HandleLookupAsset handles GET /api/v1/identities/{id}/assets/lookup?value=...
// Returns the asset matching the given identity and value.
func HandleLookupAsset(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identityID, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}
		value := r.URL.Query().Get("value")
		if value == "" {
			writeError(w, http.StatusBadRequest, "value query param required")
			return
		}

		asset, err := st.GetAssetByValue(r.Context(), identityID, value)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "asset not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to lookup asset")
			return
		}
		writeJSON(w, http.StatusOK, asset)
	}
}

// HandleEnumerateSubdomains handles POST /api/v1/assets/{asset_id}/enumerate.
// Runs on-demand subdomain brute-force for a domain asset and returns the
// discovered subdomain assets.
func HandleEnumerateSubdomains(st *store.Store) http.HandlerFunc {
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
			writeError(w, http.StatusBadRequest, "enumeration is only supported for domain assets")
			return
		}

		subdomains, err := dns.EnumerateSubdomains(r.Context(), st, assetID, asset.IdentityID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "enumeration failed: "+err.Error())
			return
		}
		if subdomains == nil {
			subdomains = []models.Asset{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"subdomains": subdomains,
			"count":      len(subdomains),
		})
	}
}
