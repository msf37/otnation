package api

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/otnation/platform/internal/config"
	"github.com/otnation/platform/internal/store"
)

// NewRouter constructs and returns a fully configured *mux.Router.
// All routes are registered under /api/v1 with shared middleware applied.
func NewRouter(st *store.Store, cfg *config.Config) *mux.Router {
	r := mux.NewRouter()

	// Global middleware (applied in outermost-first order).
	r.Use(Recover)
	r.Use(CORS)
	r.Use(RequestLogger)

	// Health check — no auth required.
	r.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}).Methods(http.MethodGet)

	api := r.PathPrefix("/api/v1").Subrouter()
	// JSON content type only on API routes, not on static/SPA routes.
	api.Use(JSONContentType)

	// -----------------------------------------------------------------------
	// Identities
	// -----------------------------------------------------------------------
	api.HandleFunc("/identities", HandleCreateIdentity(st)).Methods(http.MethodPost)
	api.HandleFunc("/identities", HandleListIdentities(st)).Methods(http.MethodGet)
	api.HandleFunc("/identities/{id}", HandleGetIdentity(st)).Methods(http.MethodGet)
	api.HandleFunc("/identities/{id}", HandleUpdateIdentity(st)).Methods(http.MethodPut)
	api.HandleFunc("/identities/{id}", HandleDeleteIdentity(st)).Methods(http.MethodDelete)

	// Seeds
	api.HandleFunc("/identities/{id}/seeds", HandleCreateSeed(st)).Methods(http.MethodPost)
	api.HandleFunc("/identities/{id}/seeds", HandleListSeeds(st)).Methods(http.MethodGet)

	// Runs (nested under identity)
	api.HandleFunc("/identities/{id}/runs", HandleCreateRun(st)).Methods(http.MethodPost)
	api.HandleFunc("/identities/{id}/runs", HandleListRuns(st)).Methods(http.MethodGet)

	// Assets (nested under identity)
	api.HandleFunc("/identities/{id}/assets", HandleListAssets(st)).Methods(http.MethodGet)
	api.HandleFunc("/identities/{id}/assets/lookup", HandleLookupAsset(st)).Methods(http.MethodGet)

	// Findings (nested under identity)
	api.HandleFunc("/identities/{id}/findings", HandleListIdentityFindings(st)).Methods(http.MethodGet)

	// -----------------------------------------------------------------------
	// Runs (top-level)
	// -----------------------------------------------------------------------
	api.HandleFunc("/runs/{run_id}", HandleGetRun(st)).Methods(http.MethodGet)

	// -----------------------------------------------------------------------
	// Assets (top-level)
	// -----------------------------------------------------------------------
	api.HandleFunc("/assets/{asset_id}", HandleGetAsset(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/scan-results", HandleGetAssetScanResults(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/findings", HandleGetAssetFindings(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/enrichment", HandleGetAssetEnrichment(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/dns-records", HandleGetAssetDNSRecords(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/subdomains", HandleGetAssetSubdomains(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/enumerate", HandleEnumerateSubdomains(st)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/port-scan", HandlePortScan(st)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/deep-scan", HandleDeepScanShodan(st, cfg)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/tls-scan", HandleGetTLSScan(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/tls-scan", HandleTLSScan(st)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/securitytrails", HandleGetSecurityTrailsEnrich(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/securitytrails", HandleSecurityTrailsEnrich(st, cfg)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/crtsh", HandleGetCrtSh(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/crtsh", HandleCrtShLookup(st)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/http-probe", HandleGetHTTPProbe(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/http-probe", HandleHTTPProbe(st)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/snmp", HandleGetSNMP(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/snmp", HandleSNMPEnum(st)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/ot-probe", HandleGetOTProbe(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/ot-probe", HandleOTProbe(st)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/bgp", HandleGetBGP(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/bgp", HandleBGPLookup(st)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/ip-whois", HandleGetIPWhois(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/ip-whois", HandleIPWhois(st)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/cve-correlate", HandleGetCVECorrelate(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/cve-correlate", HandleCVECorrelate(st)).Methods(http.MethodPost)
	api.HandleFunc("/assets/{asset_id}/vuln-notes", HandleGetVulnNotes(st)).Methods(http.MethodGet)

	// IEC 61850
	api.HandleFunc("/assets/{asset_id}/iec61850", HandleGetIEC61850(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/iec61850", HandleIEC61850Scan(st)).Methods(http.MethodPost)

	// Historian
	api.HandleFunc("/assets/{asset_id}/historian", HandleGetHistorian(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/historian", HandleHistorianDetect(st)).Methods(http.MethodPost)

	// HMI
	api.HandleFunc("/assets/{asset_id}/hmi", HandleGetHMI(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/hmi", HandleHMIFingerprint(st)).Methods(http.MethodPost)

	// ICS-CERT
	api.HandleFunc("/assets/{asset_id}/icscert", HandleGetICSCert(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/icscert", HandleICSCertSearch(st)).Methods(http.MethodPost)

	// NERC CIP
	api.HandleFunc("/assets/{asset_id}/nerc-cip", HandleGetNERCCIP(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/nerc-cip", HandleSetNERCCIP(st)).Methods(http.MethodPut)

	// IEC 60870-5-104
	api.HandleFunc("/assets/{asset_id}/iec104", HandleGetIEC104(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/iec104", HandleIEC104Scan(st)).Methods(http.MethodPost)

	// Modbus Deep
	api.HandleFunc("/assets/{asset_id}/modbus-deep", HandleGetModbusDeep(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/modbus-deep", HandleModbusDeepScan(st)).Methods(http.MethodPost)

	// DNP3 Deep
	api.HandleFunc("/assets/{asset_id}/dnp3-deep", HandleGetDNP3Deep(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/dnp3-deep", HandleDNP3DeepScan(st)).Methods(http.MethodPost)

	// ICCP
	api.HandleFunc("/assets/{asset_id}/iccp", HandleGetICCP(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/iccp", HandleICCPScan(st)).Methods(http.MethodPost)

	// EtherNet/IP Deep
	api.HandleFunc("/assets/{asset_id}/enip-deep", HandleGetEtherNetIPDeep(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/enip-deep", HandleEtherNetIPDeepScan(st)).Methods(http.MethodPost)

	// Profinet
	api.HandleFunc("/assets/{asset_id}/profinet", HandleGetProfinet(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/profinet", HandleProfinetScan(st)).Methods(http.MethodPost)

	// OPC-UA
	api.HandleFunc("/assets/{asset_id}/opcua", HandleGetOPCUA(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/opcua", HandleOPCUAScan(st)).Methods(http.MethodPost)

	// Default Credentials
	api.HandleFunc("/assets/{asset_id}/default-creds", HandleGetDefaultCreds(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/default-creds", HandleTestDefaultCreds(st)).Methods(http.MethodPost)

	// Censys
	api.HandleFunc("/assets/{asset_id}/censys", HandleGetCensys(st)).Methods(http.MethodGet)
	api.HandleFunc("/assets/{asset_id}/censys", HandleFetchCensys(st, cfg)).Methods(http.MethodPost)

	// Scan History
	api.HandleFunc("/assets/{asset_id}/history", HandleGetAssetHistory(st)).Methods(http.MethodGet)

	// Auto Scan
	api.HandleFunc("/assets/{asset_id}/auto-scan", HandleAutoScan(st)).Methods(http.MethodPost)

	// PDF Report
	api.HandleFunc("/identities/{id}/report.pdf", HandleGenerateReportPDF(st)).Methods(http.MethodGet)

	// -----------------------------------------------------------------------
	// Exploit search (CVE lookup)
	// -----------------------------------------------------------------------
	api.HandleFunc("/cves/{cve_id}/exploits", HandleSearchExploits()).Methods(http.MethodGet)

	// -----------------------------------------------------------------------
	// Findings (top-level)
	// -----------------------------------------------------------------------
	api.HandleFunc("/findings/{finding_id}", HandleGetFinding(st)).Methods(http.MethodGet)
	api.HandleFunc("/findings/{finding_id}", HandlePatchFinding(st)).Methods(http.MethodPatch)

	// -----------------------------------------------------------------------
	// Stats
	// -----------------------------------------------------------------------
	api.HandleFunc("/identities/{id}/stats", HandleGetIdentityStats(st)).Methods(http.MethodGet)

	// Zones
	api.HandleFunc("/identities/{id}/zones", HandleGetIdentityZones(st)).Methods(http.MethodGet)

	// Report
	api.HandleFunc("/identities/{id}/report", HandleGenerateReport(st)).Methods(http.MethodGet)

	// -----------------------------------------------------------------------
	// Export
	// -----------------------------------------------------------------------
	api.HandleFunc("/identities/{id}/export/assets.json", HandleExportAssetsJSON(st)).Methods(http.MethodGet)
	api.HandleFunc("/identities/{id}/export/assets.csv", HandleExportAssetsCSV(st)).Methods(http.MethodGet)
	api.HandleFunc("/identities/{id}/export/findings.json", HandleExportFindingsJSON(st)).Methods(http.MethodGet)
	api.HandleFunc("/identities/{id}/export/findings.csv", HandleExportFindingsCSV(st)).Methods(http.MethodGet)

	// CORS preflight for all routes.
	r.Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Serve static files from web/static/
	r.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))),
	)

	// SPA fallback — serve index.html for all non-API, non-static routes.
	r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "web/templates/index.html")
	})


	return r
}
