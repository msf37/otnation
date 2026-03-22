// Package shodan provides a full-featured client for the Shodan host lookup API.
package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/otnation/platform/internal/banner"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
	"github.com/rs/zerolog/log"
)

// Client is a Shodan REST API client using only stdlib HTTP.
type Client struct {
	apiKey string
	http   *http.Client
}

// New creates a new Shodan client with the given API key.
func New(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		http:   &http.Client{Timeout: 5 * time.Minute},
	}
}

// ---------------------------------------------------------------------------
// Full Shodan host response model — captures every documented field.
// ---------------------------------------------------------------------------

type HostResult struct {
	IP          string    `json:"ip_str"`
	IPInt       int64     `json:"ip"`
	Hostnames   []string  `json:"hostnames"`
	Domains     []string  `json:"domains"`
	Country     string    `json:"country_code"`
	CountryName string    `json:"country_name"`
	City        string    `json:"city"`
	RegionCode  string    `json:"region_code"`
	PostalCode  string    `json:"postal_code"`
	Latitude    float64   `json:"latitude"`
	Longitude   float64   `json:"longitude"`
	Org         string    `json:"org"`
	ISP         string    `json:"isp"`
	ASN         string    `json:"asn"`
	OS          string    `json:"os"`
	Tags        []string  `json:"tags"`
	Vulns       []string  `json:"vulns"`
	Ports       []int     `json:"ports"`
	Data        []Service `json:"data"`
	LastUpdate  string    `json:"last_update"`
	AreaCode    string    `json:"area_code"`
}

type Service struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Banner    string `json:"data"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Info      string `json:"info"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	DeviceType string `json:"devicetype"`
	CPE       []string              `json:"cpe"`
	CPE23     []string              `json:"cpe23"`
	Tags      []string              `json:"tags"`
	Timestamp string                `json:"timestamp"`
	Module    interface{}           `json:"_shodan"`
	Vulns     map[string]VulnDetail `json:"vulns"`
	HTTP      *HTTPData             `json:"http,omitempty"`
	SSL       *SSLData              `json:"ssl,omitempty"`
}

type VulnDetail struct {
	CVSS    float64  `json:"cvss"`
	Summary string   `json:"summary"`
	Refs    []string `json:"references"`
}

type HTTPData struct {
	Status      int               `json:"status"`
	Title       string            `json:"title"`
	Server      string            `json:"server"`
	Location    string            `json:"location"`
	Favicon     *FaviconData      `json:"favicon,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	SecurityTxt string            `json:"securitytxt"`
	Robots      string            `json:"robots"`
	Sitemap     string            `json:"sitemap"`
}

type FaviconData struct {
	Hash     int    `json:"hash"`
	Data     string `json:"data"`
	Location string `json:"location"`
}

type SSLData struct {
	Subject     map[string]interface{} `json:"subject"`
	Issuer      map[string]interface{} `json:"issuer"`
	Fingerprint map[string]interface{} `json:"fingerprint"`
	Versions    []string               `json:"versions"`
	Cipher      map[string]interface{} `json:"cipher"`
	Cert        map[string]interface{} `json:"cert"`
	JARM        string                 `json:"jarm"`
	Alpn        []string               `json:"alpn"`
}

// DeepScanResult is the structured response returned to the UI after a deep scan.
type DeepScanResult struct {
	Asset       models.Asset            `json:"asset"`
	ShodanRaw   *HostResult             `json:"shodan_raw"`
	ScanResults []models.ScanResult     `json:"scan_results"`
	Findings    []models.Finding        `json:"findings"`
	Enrichment  *models.EnrichmentRecord `json:"enrichment"`
}

// ---------------------------------------------------------------------------
// API methods
// ---------------------------------------------------------------------------

// LookupHost fetches the full Shodan host record for the given IP.
func (c *Client) LookupHost(ctx context.Context, ip string) (*HostResult, error) {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, c.apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("shodan: build request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shodan: http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("shodan: invalid API key")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("shodan: no data for this IP")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan: unexpected status %d for ip %s", resp.StatusCode, ip)
	}
	var result HostResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("shodan: decode response: %w", err)
	}
	return &result, nil
}

// DeepScan performs a synchronous Shodan lookup, fully updates the asset,
// stores all services as scan results, creates CVE findings, and returns
// a DeepScanResult with everything gathered.
func (c *Client) DeepScan(ctx context.Context, st *store.Store, assetID uuid.UUID, identityID uuid.UUID) (*DeepScanResult, error) {
	asset, err := st.GetAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("shodan.DeepScan: load asset: %w", err)
	}

	result, err := c.LookupHost(ctx, asset.Value)
	if err != nil {
		// Shodan has no data for this IP — return what we have without failing.
		if strings.Contains(err.Error(), "no data for this IP") {
			allScanResults, _ := st.ListScanResults(ctx, assetID)
			allFindings, _ := st.ListFindings(ctx, store.FindingFilters{AssetID: &assetID})
			log.Info().Str("ip", asset.Value).Msg("shodan: no data for this IP")
			return &DeepScanResult{
				Asset:       asset,
				ScanResults: allScanResults,
				Findings:    allFindings,
			}, nil
		}
		return nil, fmt.Errorf("shodan.DeepScan: lookup: %w", err)
	}

	// Store the full raw JSON.
	rawData, _ := json.Marshal(result)
	enrRec := models.EnrichmentRecord{
		AssetID: assetID,
		Source:  models.EnrichmentSourceShodan,
		Data:    rawData,
	}
	savedEnr, err := st.UpsertEnrichment(ctx, enrRec)
	if err != nil {
		log.Warn().Err(err).Msg("shodan: failed to upsert enrichment record")
	}

	// Always overwrite asset metadata with Shodan data — it is authoritative.
	asset.IsPublic = true
	if result.Country != "" {
		asset.CountryCode = result.Country
	}
	if result.ASN != "" {
		asnStr := strings.TrimPrefix(result.ASN, "AS")
		if n, e := strconv.ParseInt(asnStr, 10, 64); e == nil {
			asset.ASN = &n
		}
	}
	// Prefer ISP over org when available; ISP is more descriptive for hosting context.
	if result.ISP != "" {
		asset.ASNOrg = result.ISP
	} else if result.Org != "" {
		asset.ASNOrg = result.Org
	}
	// Store reverse DNS from first hostname if available.
	if len(result.Hostnames) > 0 && asset.ReverseDNS == "" {
		asset.ReverseDNS = result.Hostnames[0]
	}
	updatedAsset, err := st.UpsertAsset(ctx, asset)
	if err != nil {
		log.Warn().Err(err).Msg("shodan: failed to update asset")
		updatedAsset = asset
	}

	var newScanResults []models.ScanResult

	for _, svc := range result.Data {
		transport := svc.Transport
		if transport == "" {
			transport = "tcp"
		}

		// Use banner classifier for service category; prefer Shodan product name.
		cls := banner.Classify(svc.Port, svc.Banner)
		serviceName := svc.Product
		if serviceName == "" {
			serviceName = cls.ServiceName
		}
		category := cls.Category
		confidence := cls.Confidence

		// Build rich banner string: product + version + info.
		bannerStr := svc.Banner
		if svc.Product != "" && svc.Version != "" {
			bannerStr = svc.Product + " " + svc.Version
			if svc.Info != "" {
				bannerStr += " (" + svc.Info + ")"
			}
			if svc.Banner != "" {
				bannerStr += "\n" + svc.Banner
			}
		}

		// Build evidence JSON with every available Shodan service field.
		svcEvidence := map[string]interface{}{
			"product":     svc.Product,
			"version":     svc.Version,
			"info":        svc.Info,
			"device_type": svc.DeviceType,
			"hostname":    svc.Hostname,
			"os":          svc.OS,
			"cpe":         svc.CPE,
			"cpe23":       svc.CPE23,
			"tags":        svc.Tags,
			"timestamp":   svc.Timestamp,
		}
		if svc.HTTP != nil {
			svcEvidence["http"] = svc.HTTP
		}
		if svc.SSL != nil {
			svcEvidence["ssl"] = svc.SSL
		}
		rawEvidence, _ := json.Marshal(svcEvidence)

		sr := models.ScanResult{
			AssetID:         assetID,
			IdentityID:      identityID,
			Port:            svc.Port,
			Protocol:        transport,
			ServiceName:     serviceName,
			Banner:          bannerStr,
			ServiceCategory: category,
			Confidence:      confidence,
			RawResponse:     rawEvidence,
			ScannedAt:       time.Now(),
		}

		// InsertScanResult now does ON CONFLICT DO UPDATE — always upsert.
		saved, err := st.InsertScanResult(ctx, sr)
		if err != nil {
			log.Warn().Err(err).Int("port", svc.Port).Msg("shodan: failed to upsert scan result")
		} else {
			newScanResults = append(newScanResults, saved)
		}

		// Per-service CVE findings.
		for cveID, vuln := range svc.Vulns {
			insertCVEFinding(ctx, st, assetID, identityID, cveID, vuln.CVSS, vuln.Summary, svc.Port)
		}
	}

	// Top-level CVEs (may not have per-service detail).
	for _, cveID := range result.Vulns {
		cvss := 0.0
		summary := ""
		for _, svc := range result.Data {
			if v, ok := svc.Vulns[cveID]; ok {
				cvss = v.CVSS
				summary = v.Summary
				break
			}
		}
		insertCVEFinding(ctx, st, assetID, identityID, cveID, cvss, summary, 0)
	}

	// Reload updated scan results and findings for the response.
	allScanResults, _ := st.ListScanResults(ctx, assetID)
	allFindings, _ := st.ListFindings(ctx, store.FindingFilters{AssetID: &assetID})

	log.Info().
		Str("ip", asset.Value).
		Int("services", len(result.Data)).
		Int("cves", len(result.Vulns)).
		Str("country", result.Country).
		Str("org", result.Org).
		Msg("shodan: deep scan complete")

	return &DeepScanResult{
		Asset:       updatedAsset,
		ShodanRaw:   result,
		ScanResults: allScanResults,
		Findings:    allFindings,
		Enrichment:  &savedEnr,
	}, nil
}

// EnrichAsset is the async job-compatible variant used by the worker.
func (c *Client) EnrichAsset(ctx context.Context, st *store.Store, assetID uuid.UUID, identityID uuid.UUID) error {
	_, err := c.DeepScan(ctx, st, assetID, identityID)
	return err
}

func insertCVEFinding(ctx context.Context, st *store.Store, assetID, identityID uuid.UUID, cveID string, cvss float64, summary string, port int) {
	sev := cvssToSeverity(cvss)
	evidence := map[string]interface{}{
		"cve":  cveID,
		"cvss": cvss,
		"port": port,
	}
	evidenceBytes, _ := json.Marshal(evidence)
	finding := models.Finding{
		IdentityID:  identityID,
		AssetID:     assetID,
		Title:       "CVE: " + cveID,
		Description: summary,
		Severity:    sev,
		Category:    "vulnerability",
		Evidence:    evidenceBytes,
	}
	if _, err := st.InsertFinding(ctx, finding); err != nil {
		log.Debug().Err(err).Str("cve", cveID).Msg("shodan: skipped duplicate CVE finding")
	}
}

func cvssToSeverity(cvss float64) models.SeverityLevel {
	switch {
	case cvss >= 9.0:
		return models.SeverityCritical
	case cvss >= 7.0:
		return models.SeverityHigh
	case cvss >= 4.0:
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}
