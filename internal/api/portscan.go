package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/scanner"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandlePortScan handles POST /api/v1/assets/{asset_id}/port-scan
// Query param: profile=light|standard|deep  (default: standard)
func HandlePortScan(st *store.Store) http.HandlerFunc {
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

		if asset.Type != "ip" {
			writeError(w, http.StatusBadRequest, "port scanning is only supported for IP assets")
			return
		}

		profileParam := r.URL.Query().Get("profile")
		profile := scanner.NmapProfileStandard
		switch profileParam {
		case "light":
			profile = scanner.NmapProfileLight
		case "deep":
			profile = scanner.NmapProfileDeep
		}

		result, err := scanner.NmapScanAsset(r.Context(), st, assetID, asset.IdentityID, profile)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "port scan failed: "+err.Error())
			return
		}

		scanResults := result.ScanResults

		// Snapshot port history and detect new open ports
		if scanResults != nil {
			ports := make([]int, 0, len(scanResults))
			for _, sr := range scanResults {
				ports = append(ports, sr.Port)
			}
			portsJSON, _ := json.Marshal(ports)
			prev, prevErr := st.GetLatestScanHistory(r.Context(), assetID)
			if prevErr == nil {
				// Compare with previous snapshot
				var prevPorts []int
				_ = json.Unmarshal(prev.OpenPorts, &prevPorts)
				prevSet := map[int]bool{}
				for _, p := range prevPorts {
					prevSet[p] = true
				}
				for _, p := range ports {
					if !prevSet[p] {
						// New port detected
						f := models.Finding{
							IdentityID:  asset.IdentityID, AssetID: asset.ID,
							Title:       fmt.Sprintf("New Open Port Detected: %d", p),
							Description: fmt.Sprintf("Port %d was not seen in the previous scan of %s. New port exposure detected.", p, asset.Value),
							Severity:    models.SeverityMedium,
							Category:    "network_change",
							Protocol:    "",
							Vendor:      "",
						}
						if _, err := st.InsertFinding(r.Context(), f); err != nil {
							log.Debug().Err(err).Int("port", p).Msg("portscan: skipped duplicate new-port finding")
						}
					}
				}
			}
			_, _ = st.InsertScanHistory(r.Context(), assetID, portsJSON)
		}

		// Auto-classify NERC CIP if OT ports found
		otPorts := map[int]bool{502: true, 20000: true, 2404: true, 102: true, 44818: true}
		hasOTPorts := false
		for _, sr := range scanResults {
			if otPorts[sr.Port] {
				hasOTPorts = true
				break
			}
		}
		if hasOTPorts {
			existing, _ := st.GetAssetNERCCIP(r.Context(), assetID)
			if !existing.BCSAsset {
				classification := models.NERCCIPClassification{
					BCSAsset:     true,
					AssetType:    "BES Cyber Asset",
					ImpactRating: "High",
					Zone:         "Control",
					CIPStandards: []string{"CIP-002", "CIP-005", "CIP-007", "CIP-010", "CIP-013"},
				}
				_ = st.UpdateAssetNERCCIP(r.Context(), assetID, classification)
			}
		}

		writeJSON(w, http.StatusOK, result)
	}
}
