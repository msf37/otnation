// Package ipwhois retrieves IP WHOIS / geolocation information from ipwhois.app.
package ipwhois

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrNoData is returned when the ipwhois.app API has no data for the given IP.
var ErrNoData = errors.New("ipwhois: no data for this IP")

// Result holds the WHOIS / ASN data for a single IP address.
type Result struct {
	IP          string `json:"ip"`
	Org         string `json:"org"`
	ISP         string `json:"isp"`
	ASN         string `json:"asn"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	Region      string `json:"region"`
	Timezone    string `json:"timezone"`
}

// ipWhoisResponse maps the relevant fields from ipwhois.app.
type ipWhoisResponse struct {
	IP          string `json:"ip"`
	Success     bool   `json:"success"`
	Org         string `json:"org"`
	ISP         string `json:"isp"`
	ASN         string `json:"asn"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	Region      string `json:"region"`
	Timezone    string `json:"timezone"`
	Message     string `json:"message"`
}

// Lookup calls ipwhois.app and returns WHOIS/geolocation information.
func Lookup(ctx context.Context, ip string) (*Result, error) {
	url := fmt.Sprintf("https://ipwhois.app/json/%s", ip)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "otnation-platform/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ipwhois: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipwhois: API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("ipwhois: failed to read response: %w", err)
	}

	var raw ipWhoisResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("ipwhois: failed to parse response: %w", err)
	}

	if !raw.Success {
		return nil, ErrNoData
	}

	result := &Result{
		IP:          raw.IP,
		Org:         raw.Org,
		ISP:         raw.ISP,
		ASN:         raw.ASN,
		Country:     raw.Country,
		CountryCode: raw.CountryCode,
		City:        raw.City,
		Region:      raw.Region,
		Timezone:    raw.Timezone,
	}

	if result.IP == "" {
		return nil, ErrNoData
	}

	return result, nil
}
