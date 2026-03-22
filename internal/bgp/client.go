// Package bgp retrieves BGP/ASN/netblock information for a given IP.
// Uses ip-api.com (free, no API key required).
package bgp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrNoData is returned when no BGP data could be found for the given IP.
var ErrNoData = errors.New("bgp: no data for this IP")

// Result holds the BGP/ASN data for a single IP address.
type Result struct {
	IP          string   `json:"ip"`
	ASN         string   `json:"asn"`
	ASNName     string   `json:"asn_name"`
	Prefix      string   `json:"prefix"`
	CountryCode string   `json:"country_code"`
	Country     string   `json:"country"`
	Region      string   `json:"region"`
	City        string   `json:"city"`
	ISP         string   `json:"isp"`
	Org         string   `json:"org"`
	Prefixes    []string `json:"prefixes"`
}

// ipAPIResponse maps the ip-api.com JSON response fields we need.
type ipAPIResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Region      string `json:"regionName"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	AS          string `json:"as"`      // e.g. "AS13335 Cloudflare, Inc."
	ASName      string `json:"asname"`  // e.g. "CLOUDFLARENET"
	Query       string `json:"query"`
}

// Lookup calls ip-api.com and returns BGP/ASN information for the given IP.
func Lookup(ctx context.Context, ip string) (*Result, error) {
	url := fmt.Sprintf("https://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,isp,org,as,asname,query", ip)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "otnation-platform/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bgp: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bgp: API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("bgp: failed to read response: %w", err)
	}

	var apiResp ipAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("bgp: failed to parse response: %w", err)
	}

	if apiResp.Status != "success" {
		if apiResp.Message != "" {
			return nil, fmt.Errorf("bgp: %s", apiResp.Message)
		}
		return nil, ErrNoData
	}

	// AS field is like "AS13335 Cloudflare, Inc." — split into number and name.
	asn := apiResp.AS
	asnName := apiResp.ASName
	if asnName == "" && strings.HasPrefix(asn, "AS") {
		parts := strings.SplitN(asn, " ", 2)
		if len(parts) == 2 {
			asnName = parts[1]
		}
	}

	result := &Result{
		IP:          apiResp.Query,
		ASN:         asn,
		ASNName:     asnName,
		CountryCode: apiResp.CountryCode,
		Country:     apiResp.Country,
		Region:      apiResp.Region,
		City:        apiResp.City,
		ISP:         apiResp.ISP,
		Org:         apiResp.Org,
	}

	if result.IP == "" {
		result.IP = ip
	}

	if result.ASN == "" && result.Org == "" {
		return nil, ErrNoData
	}

	return result, nil
}
