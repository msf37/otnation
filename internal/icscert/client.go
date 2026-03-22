// Package icscert queries CISA KEV for ICS-related advisories.
package icscert

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

// ErrNoAdvisories is returned when no ICS advisories match the search keyword.
var ErrNoAdvisories = errors.New("icscert: no ICS advisories found")

// Advisory holds information about a single ICS advisory.
type Advisory struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	CVSS        string `json:"cvss"`
	Description string `json:"description"`
	URL         string `json:"url"`
	DateAdded   string `json:"date_added"`
}

// Result holds all advisories and the total count.
type Result struct {
	Advisories []Advisory `json:"advisories"`
	Total      int        `json:"total"`
}

// otKeywords is the list of OT-related vendor/product keywords used to filter CISA KEV.
var otKeywords = []string{
	"siemens", "schneider", "abb", "ge", "honeywell", "rockwell",
	"moxa", "mitsubishi", "delta", "sel", "schweitzer", "emerson",
	"yokogawa", "beckhoff", "wago", "phoenix contact", "advantech",
	"aveva", "wonderware", "osisoft", "dnp3", "modbus", "scada",
	"ics", "hmi", "plc", "rtu", "historian", "intouch", "wincc",
	"factorytalk", "ignition", "cimplicity", "ifix", "proficy",
}

// cisaKEVURL is the CISA Known Exploited Vulnerabilities feed.
const cisaKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type cisaKEVResponse struct {
	Vulnerabilities []struct {
		CVEID             string `json:"cveID"`
		VendorProject     string `json:"vendorProject"`
		Product           string `json:"product"`
		VulnerabilityName string `json:"vulnerabilityName"`
		DateAdded         string `json:"dateAdded"`
		ShortDescription  string `json:"shortDescription"`
		RequiredAction    string `json:"requiredAction"`
	} `json:"vulnerabilities"`
}

// Search searches CISA KEV for ICS-related advisories matching the keyword.
func Search(ctx context.Context, keyword string) (*Result, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cisaKEVURL, nil)
	if err != nil {
		return nil, fmt.Errorf("icscert: build request: %w", err)
	}
	req.Header.Set("User-Agent", "OTNation-Platform/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("icscert: fetch CISA KEV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("icscert: CISA KEV returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("icscert: read body: %w", err)
	}

	var kevData cisaKEVResponse
	if err := json.Unmarshal(body, &kevData); err != nil {
		return nil, fmt.Errorf("icscert: parse JSON: %w", err)
	}

	kwLower := strings.ToLower(keyword)

	var advisories []Advisory
	for _, v := range kevData.Vulnerabilities {
		vendorLower := strings.ToLower(v.VendorProject)
		productLower := strings.ToLower(v.Product)
		nameLower := strings.ToLower(v.VulnerabilityName)
		descLower := strings.ToLower(v.ShortDescription)

		combined := vendorLower + " " + productLower + " " + nameLower + " " + descLower

		// Must match the user-supplied keyword.
		if kwLower != "" && !strings.Contains(combined, kwLower) {
			continue
		}

		// Must also contain at least one OT keyword to stay relevant.
		isOT := false
		for _, kw := range otKeywords {
			if strings.Contains(combined, kw) {
				isOT = true
				break
			}
		}
		if !isOT {
			continue
		}

		advisories = append(advisories, Advisory{
			ID:          v.CVEID,
			Title:       v.VulnerabilityName,
			Vendor:      v.VendorProject,
			Product:     v.Product,
			Description: v.ShortDescription,
			URL:         "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
			DateAdded:   v.DateAdded,
		})
	}

	// If keyword-filtered results are empty but keyword is an OT term, try without the keyword filter.
	if len(advisories) == 0 && kwLower != "" {
		for _, v := range kevData.Vulnerabilities {
			combined := strings.ToLower(v.VendorProject + " " + v.Product + " " + v.VulnerabilityName + " " + v.ShortDescription)
			isOT := false
			for _, kw := range otKeywords {
				if strings.Contains(combined, kw) {
					isOT = true
					break
				}
			}
			if isOT {
				advisories = append(advisories, Advisory{
					ID:          v.CVEID,
					Title:       v.VulnerabilityName,
					Vendor:      v.VendorProject,
					Product:     v.Product,
					Description: v.ShortDescription,
					URL:         "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
					DateAdded:   v.DateAdded,
				})
			}
		}
	}

	if len(advisories) == 0 {
		return nil, ErrNoAdvisories
	}

	// Cap at 100 results.
	if len(advisories) > 100 {
		advisories = advisories[:100]
	}

	return &Result{
		Advisories: advisories,
		Total:      len(advisories),
	}, nil
}
