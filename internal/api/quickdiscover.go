package api

import (
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/dns"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/quickdiscover"
	"github.com/otnation/platform/internal/store"
)

// HandleQuickDiscover handles POST /api/v1/assets/{asset_id}/quick-discover.
// For IP assets: probes the /24 subnet on common ports, records live hosts,
// performs reverse-DNS lookups, and saves new assets.
// For domain/subdomain assets: runs subdomain brute-force enumeration.
func HandleQuickDiscover(st *store.Store) http.HandlerFunc {
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

		var result *quickdiscover.Result

		switch asset.Type {
		case models.AssetTypeIP:
			result, err = quickdiscover.DiscoverFromIP(r.Context(), st, asset)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "quick discover failed: "+err.Error())
				return
			}

		case models.AssetTypeDomain, models.AssetTypeSubdomain:
			result, err = quickdiscover.DiscoverFromDomain(r.Context(), st, asset, dns.EnumerateSubdomains)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "quick discover failed: "+err.Error())
				return
			}

		default:
			writeError(w, http.StatusBadRequest, "quick discover is not supported for asset type: "+string(asset.Type))
			return
		}

		writeJSON(w, http.StatusOK, result)
	}
}
