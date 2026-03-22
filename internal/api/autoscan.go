package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/dnp3deep"
	"github.com/otnation/platform/internal/enipdeep"
	"github.com/otnation/platform/internal/iccp"
	"github.com/otnation/platform/internal/iec104"
	"github.com/otnation/platform/internal/iec61850"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/modbusdeep"
	"github.com/otnation/platform/internal/opcua"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// HandleAutoScan runs a port scan then auto-chains OT protocol scans based on open ports.
func HandleAutoScan(st *store.Store) http.HandlerFunc {
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
		if asset.Type != models.AssetTypeIP {
			writeError(w, http.StatusBadRequest, "auto-scan requires an IP asset")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		// Get existing scan results to determine which OT protocols to probe
		scanResults, err := st.ListScanResults(r.Context(), assetID)
		if err != nil {
			scanResults = nil
		}

		openPorts := map[int]bool{}
		for _, sr := range scanResults {
			openPorts[sr.Port] = true
		}

		type scanSummary struct {
			Protocol string `json:"protocol"`
			Status   string `json:"status"`
			Findings int    `json:"findings"`
		}
		var summary []scanSummary
		var allFindings []models.Finding

		runScan := func(protocol string, fn func() (interface{}, []models.Finding, error)) {
			res, findings, err := fn()
			if err != nil {
				log.Debug().Err(err).Str("protocol", protocol).Msg("autoscan: scan returned no response")
				summary = append(summary, scanSummary{Protocol: protocol, Status: "no_response", Findings: 0})
				return
			}
			_ = res
			allFindings = append(allFindings, findings...)
			summary = append(summary, scanSummary{Protocol: protocol, Status: "ok", Findings: len(findings)})
		}

		// IEC 104 (port 2404)
		if openPorts[2404] {
			runScan("iec104", func() (interface{}, []models.Finding, error) {
				return autoRunIEC104(ctx, st, asset, assetID)
			})
		}

		// Modbus deep (port 502)
		if openPorts[502] {
			runScan("modbus_deep", func() (interface{}, []models.Finding, error) {
				return autoRunModbusDeep(ctx, st, asset, assetID)
			})
		}

		// DNP3 deep (port 20000)
		if openPorts[20000] {
			runScan("dnp3_deep", func() (interface{}, []models.Finding, error) {
				return autoRunDNP3Deep(ctx, st, asset, assetID)
			})
		}

		// EtherNet/IP deep (port 44818)
		if openPorts[44818] {
			runScan("enip_deep", func() (interface{}, []models.Finding, error) {
				return autoRunEtherNetIPDeep(ctx, st, asset, assetID)
			})
		}

		// IEC 61850 + ICCP (port 102)
		if openPorts[102] {
			runScan("iec61850", func() (interface{}, []models.Finding, error) {
				return autoRunIEC61850(ctx, st, asset, assetID)
			})
			runScan("iccp", func() (interface{}, []models.Finding, error) {
				return autoRunICCP(ctx, st, asset, assetID)
			})
		}

		// OPC-UA (port 4840)
		if openPorts[4840] {
			runScan("opcua", func() (interface{}, []models.Finding, error) {
				return autoRunOPCUA(ctx, st, asset, assetID)
			})
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"asset_id":           assetID,
			"protocols_scanned":  len(summary),
			"summary":            summary,
			"findings_generated": len(allFindings),
			"findings":           allFindings,
		})
	}
}

func autoRunIEC104(ctx context.Context, st *store.Store, asset models.Asset, assetID [16]byte) (interface{}, []models.Finding, error) {
	result, err := iec104.Scan(asset.Value)
	if err != nil {
		return nil, nil, err
	}
	rawData, _ := json.Marshal(result)
	rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceIEC104, Data: rawData}
	_, _ = st.UpsertEnrichment(ctx, rec)
	var findings []models.Finding
	if result.Responded {
		f := models.Finding{
			IdentityID:  asset.IdentityID, AssetID: asset.ID,
			Title:       "IEC 60870-5-104 Service Exposed",
			Description: "IEC 60870-5-104 service detected at " + asset.Value + " port 2404 during auto-scan.",
			Severity:    models.SeverityCritical, Category: "ot", Protocol: "iec104", Vendor: "IEC",
		}
		if saved, err := st.InsertFinding(ctx, f); err == nil {
			findings = append(findings, saved)
		}
	}
	return result, findings, nil
}

func autoRunModbusDeep(ctx context.Context, st *store.Store, asset models.Asset, assetID [16]byte) (interface{}, []models.Finding, error) {
	result, err := modbusdeep.Scan(asset.Value)
	if err != nil {
		return nil, nil, err
	}
	rawData, _ := json.Marshal(result)
	rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceModbusDeep, Data: rawData}
	_, _ = st.UpsertEnrichment(ctx, rec)
	var findings []models.Finding
	f := models.Finding{
		IdentityID:  asset.IdentityID, AssetID: asset.ID,
		Title:       "Modbus Deep Register Exposure",
		Description: "Modbus register data was successfully read from " + asset.Value + " during auto-scan.",
		Severity:    models.SeverityHigh, Category: "ot", Protocol: "modbus", Vendor: "IEC",
	}
	if saved, err := st.InsertFinding(ctx, f); err == nil {
		findings = append(findings, saved)
	}
	return result, findings, nil
}

func autoRunDNP3Deep(ctx context.Context, st *store.Store, asset models.Asset, assetID [16]byte) (interface{}, []models.Finding, error) {
	result, err := dnp3deep.Scan(asset.Value)
	if err != nil {
		return nil, nil, err
	}
	rawData, _ := json.Marshal(result)
	rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceDNP3Deep, Data: rawData}
	_, _ = st.UpsertEnrichment(ctx, rec)
	var findings []models.Finding
	if result.Responded {
		f := models.Finding{
			IdentityID:  asset.IdentityID, AssetID: asset.ID,
			Title:       "DNP3 Data Point Exposure",
			Description: "DNP3 protocol responded at " + asset.Value + " port 20000 during auto-scan.",
			Severity:    models.SeverityCritical, Category: "ot", Protocol: "dnp3", Vendor: "IEEE",
		}
		if saved, err := st.InsertFinding(ctx, f); err == nil {
			findings = append(findings, saved)
		}
	}
	return result, findings, nil
}

func autoRunEtherNetIPDeep(ctx context.Context, st *store.Store, asset models.Asset, assetID [16]byte) (interface{}, []models.Finding, error) {
	result, err := enipdeep.Scan(asset.Value)
	if err != nil {
		return nil, nil, err
	}
	rawData, _ := json.Marshal(result)
	rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceEtherNetIPDeep, Data: rawData}
	_, _ = st.UpsertEnrichment(ctx, rec)
	var findings []models.Finding
	if result.Responded && len(result.Tags) > 0 {
		f := models.Finding{
			IdentityID:  asset.IdentityID, AssetID: asset.ID,
			Title:       "EtherNet/IP CIP Deep Exposure",
			Description: "EtherNet/IP CIP tags were enumerated from " + asset.Value + " during auto-scan.",
			Severity:    models.SeverityHigh, Category: "ot", Protocol: "enip", Vendor: "ODVA",
		}
		if saved, err := st.InsertFinding(ctx, f); err == nil {
			findings = append(findings, saved)
		}
	}
	return result, findings, nil
}

func autoRunIEC61850(ctx context.Context, st *store.Store, asset models.Asset, assetID [16]byte) (interface{}, []models.Finding, error) {
	result, err := iec61850.Scan(asset.Value)
	if err != nil {
		return nil, nil, err
	}
	rawData, _ := json.Marshal(result)
	rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceIEC61850, Data: rawData}
	_, _ = st.UpsertEnrichment(ctx, rec)
	var findings []models.Finding
	if result.Responded && result.DeviceType == "IEC 61850 MMS" {
		f := models.Finding{
			IdentityID:  asset.IdentityID, AssetID: asset.ID,
			Title:       "IEC 61850 MMS IED Exposed",
			Description: "IEC 61850 MMS IED detected at " + asset.Value + " port 102 during auto-scan.",
			Severity:    models.SeverityCritical, Category: "ot", Protocol: "iec61850", Vendor: "IEC",
		}
		if saved, err := st.InsertFinding(ctx, f); err == nil {
			findings = append(findings, saved)
		}
	}
	return result, findings, nil
}

func autoRunICCP(ctx context.Context, st *store.Store, asset models.Asset, assetID [16]byte) (interface{}, []models.Finding, error) {
	result, err := iccp.Scan(asset.Value)
	if err != nil {
		return nil, nil, err
	}
	rawData, _ := json.Marshal(result)
	rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceICCP, Data: rawData}
	_, _ = st.UpsertEnrichment(ctx, rec)
	var findings []models.Finding
	if result.Responded && result.DeviceType == "ICCP/TASE.2 (IEC 60870-6)" {
		f := models.Finding{
			IdentityID:  asset.IdentityID, AssetID: asset.ID,
			Title:       "ICCP/TASE.2 Inter-Control Center Protocol Exposed",
			Description: "ICCP/TASE.2 protocol detected at " + asset.Value + " port 102 during auto-scan.",
			Severity:    models.SeverityCritical, Category: "ot", Protocol: "iccp", Vendor: "IEC",
		}
		if saved, err := st.InsertFinding(ctx, f); err == nil {
			findings = append(findings, saved)
		}
	}
	return result, findings, nil
}

func autoRunOPCUA(ctx context.Context, st *store.Store, asset models.Asset, assetID [16]byte) (interface{}, []models.Finding, error) {
	result, err := opcua.Scan(asset.Value)
	if err != nil {
		return nil, nil, err
	}
	rawData, _ := json.Marshal(result)
	rec := models.EnrichmentRecord{AssetID: assetID, Source: models.EnrichmentSourceOPCUA, Data: rawData}
	_, _ = st.UpsertEnrichment(ctx, rec)
	var findings []models.Finding
	if result.Responded {
		f := models.Finding{
			IdentityID:  asset.IdentityID, AssetID: asset.ID,
			Title:       "OPC-UA Server Exposed",
			Description: "OPC-UA server detected at " + asset.Value + " port 4840 during auto-scan.",
			Severity:    models.SeverityMedium, Category: "ot", Protocol: "opcua", Vendor: "OPC Foundation",
		}
		if saved, err := st.InsertFinding(ctx, f); err == nil {
			findings = append(findings, saved)
		}
	}
	return result, findings, nil
}
