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

// otPorts is the set of well-known OT protocol ports.
var otPorts = map[int]bool{
	102:   true, // IEC 61850 / S7 ISO-TSAP
	502:   true, // Modbus TCP
	20000: true, // DNP3
	44818: true, // EtherNet/IP
	47808: true, // BACnet
	4840:  true, // OPC-UA
	2222:  true, // UMAS (Schneider)
	20222: true, // Citect SCADA
	55555: true, // Honeywell Experion
}

// itPorts is the set of well-known IT service ports.
var itPorts = map[int]bool{
	80:   true,
	443:  true,
	22:   true,
	3389: true,
	8080: true,
	8443: true,
}

// HandleGetIdentityZones handles GET /api/v1/identities/{id}/zones.
// Returns assets grouped by their inferred or NERC-CIP-classified network zone.
func HandleGetIdentityZones(st *store.Store) http.HandlerFunc {
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

		assets, err := st.ListAssets(r.Context(), store.AssetFilters{
			IdentityID: &id,
			Limit:      2000,
			Page:       1,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list assets")
			return
		}

		// Build a map of assetID -> open ports.
		assetPortMap := map[string]map[int]bool{}
		for _, a := range assets {
			scanResults, err := st.ListScanResults(r.Context(), a.ID)
			if err != nil {
				continue
			}
			portSet := map[int]bool{}
			for _, sr := range scanResults {
				portSet[sr.Port] = true
			}
			assetPortMap[a.ID.String()] = portSet
		}

		// Zone groupings.
		zones := map[string][]models.Asset{
			"Control":    {},
			"DMZ":        {},
			"Enterprise": {},
			"Unknown":    {},
		}

		for _, a := range assets {
			// Try NERC CIP classification first.
			zone := ""
			cipClass, err := st.GetAssetNERCCIP(r.Context(), a.ID)
			if err == nil && cipClass.Zone != "" {
				zone = cipClass.Zone
			}

			if zone == "" {
				portSet := assetPortMap[a.ID.String()]
				zone = inferZone(portSet)
			}

			switch zone {
			case "Control":
				zones["Control"] = append(zones["Control"], a)
			case "DMZ":
				zones["DMZ"] = append(zones["DMZ"], a)
			case "Enterprise":
				zones["Enterprise"] = append(zones["Enterprise"], a)
			default:
				zones["Unknown"] = append(zones["Unknown"], a)
			}
		}

		// Build JSON-compatible zone summary with NERC CIP classification if available.
		type assetWithZone struct {
			models.Asset
			Zone           string                     `json:"zone"`
			NERCCIPClass   *models.NERCCIPClassification `json:"nerc_cip,omitempty"`
		}

		result := map[string][]assetWithZone{}
		for zoneName, assetList := range zones {
			for _, a := range assetList {
				entry := assetWithZone{Asset: a, Zone: zoneName}
				cipClass, err := st.GetAssetNERCCIP(r.Context(), a.ID)
				if err == nil && (cipClass.BCSAsset || cipClass.Zone != "" || cipClass.ImpactRating != "") {
					c := cipClass
					entry.NERCCIPClass = &c
				}
				result[zoneName] = append(result[zoneName], entry)
			}
		}

		// Include zone counts in the response envelope.
		counts := map[string]int{}
		for k, v := range result {
			counts[k] = len(v)
		}

		rawZones, _ := json.Marshal(result)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"zones":`))
		_, _ = w.Write(rawZones)
		_, _ = w.Write([]byte(`}`))
	}
}

// inferZone determines the network zone of an asset based on its open ports.
func inferZone(portSet map[int]bool) string {
	if len(portSet) == 0 {
		return "Unknown"
	}

	hasOT := false
	hasIT := false

	for p := range portSet {
		if otPorts[p] {
			hasOT = true
		}
		if itPorts[p] {
			hasIT = true
		}
	}

	switch {
	case hasOT && hasIT:
		return "DMZ"
	case hasOT:
		return "Control"
	case hasIT:
		return "Enterprise"
	default:
		return "Unknown"
	}
}
