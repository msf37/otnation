// Package cve correlates open port banners with CVEs from the NVD NIST API.
package cve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/otnation/platform/internal/models"
)

// ErrNoData is returned when no CVE data could be found for any service.
var ErrNoData = errors.New("cve: no CVE data found")

// Exploit represents a known public exploit for a CVE.
type Exploit struct {
	Source string `json:"source"` // e.g. "exploit-db", "packetstorm", "github"
	URL    string `json:"url"`
	Title  string `json:"title,omitempty"`
}

// CVE represents a single vulnerability entry.
type CVE struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSSScore   float64   `json:"cvss_score"`
	URL         string    `json:"url"`
	Exploits    []Exploit `json:"exploits,omitempty"`
}

// ServiceCVEs groups CVEs by the service/port they relate to.
type ServiceCVEs struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
	CVEs    []CVE  `json:"cves"`
}

// Result is the top-level CVE correlation result.
type Result struct {
	IP       string        `json:"ip"`
	Services []ServiceCVEs `json:"services"`
}

// nvdResponse maps the NVD NIST CVE 2.0 API response.
type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			References []struct {
				URL    string   `json:"url"`
				Source string   `json:"source"`
				Tags   []string `json:"tags"`
			} `json:"references"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CVSSMetricV2 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// exploitSources maps URL substrings to a friendly source label.
var exploitSources = []struct {
	substr string
	label  string
}{
	{"exploit-db.com", "exploit-db"},
	{"exploitdb.com", "exploit-db"},
	{"packetstormsecurity.com", "packetstorm"},
	{"rapid7.com/db", "rapid7"},
	{"metasploit.com", "metasploit"},
	{"github.com/rapid7/metasploit", "metasploit"},
	{"github.com/offensive-security", "exploit-db"},
	{"vulhub.org", "vulhub"},
	{"sploitus.com", "sploitus"},
	{"0day.today", "0day.today"},
}

// extractExploits pulls exploit references from NVD reference list.
func extractExploits(refs []struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}) []Exploit {
	var exploits []Exploit
	seen := map[string]bool{}

	for _, ref := range refs {
		if seen[ref.URL] {
			continue
		}
		// Check if tagged as Exploit.
		isExploit := false
		for _, tag := range ref.Tags {
			if strings.EqualFold(tag, "Exploit") {
				isExploit = true
				break
			}
		}
		// Also check URL against known exploit sources.
		source := ""
		for _, es := range exploitSources {
			if strings.Contains(strings.ToLower(ref.URL), es.substr) {
				source = es.label
				isExploit = true
				break
			}
		}
		if !isExploit {
			continue
		}
		if source == "" {
			source = "external"
		}
		seen[ref.URL] = true
		exploits = append(exploits, Exploit{
			Source: source,
			URL:    ref.URL,
		})
	}
	return exploits
}

// Correlate looks up CVEs for each open-port service discovered in scanResults.
// It also accepts a list of known CVE IDs (e.g. from Shodan) to fetch directly by ID.
func Correlate(ctx context.Context, ip string, scanResults []models.ScanResult, knownCVEIDs []string) (*Result, error) {
	result := &Result{IP: ip}

	client := &http.Client{Timeout: 30 * time.Second}

	// --- Keyword-based lookup from scan result banners ---
	for _, sr := range scanResults {
		keyword := buildKeyword(sr)
		if keyword == "" {
			continue
		}

		cves, err := queryNVD(ctx, client, keyword)
		if err != nil {
			continue
		}
		if len(cves) == 0 {
			continue
		}

		svc := ServiceCVEs{
			Port:    sr.Port,
			Service: sr.ServiceName,
			Banner:  sr.Banner,
			CVEs:    cves,
		}
		result.Services = append(result.Services, svc)
	}

	// --- Direct CVE ID lookup (from Shodan or other sources) ---
	if len(knownCVEIDs) > 0 {
		var shodanCVEs []CVE
		seen := map[string]bool{}
		// Deduplicate against what banner search already found.
		for _, svc := range result.Services {
			for _, c := range svc.CVEs {
				seen[c.ID] = true
			}
		}
		for _, id := range knownCVEIDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			c, err := fetchCVEByID(ctx, client, id)
			if err != nil {
				continue
			}
			shodanCVEs = append(shodanCVEs, *c)
		}
		if len(shodanCVEs) > 0 {
			result.Services = append(result.Services, ServiceCVEs{
				Port:    0,
				Service: "Shodan Intelligence",
				Banner:  "",
				CVEs:    shodanCVEs,
			})
		}
	}

	if len(result.Services) == 0 {
		return result, ErrNoData
	}

	return result, nil
}

// fetchCVEByID retrieves a single CVE from NVD by its exact ID.
func fetchCVEByID(ctx context.Context, client *http.Client, cveID string) (*CVE, error) {
	apiURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	params := url.Values{}
	params.Set("cveId", cveID)
	fullURL := apiURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "otnation-platform/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cve: NVD request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cve: NVD returned status %d for %s", resp.StatusCode, cveID)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var nvd nvdResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil, err
	}
	if len(nvd.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("cve: no NVD entry for %s", cveID)
	}

	v := nvd.Vulnerabilities[0].CVE
	desc := ""
	for _, d := range v.Descriptions {
		if d.Lang == "en" {
			desc = d.Value
			break
		}
	}
	if desc == "" && len(v.Descriptions) > 0 {
		desc = v.Descriptions[0].Value
	}
	score, severity := extractScore(v.Metrics)
	exploits := extractExploits(v.References)

	return &CVE{
		ID:          v.ID,
		Description: desc,
		Severity:    severity,
		CVSSScore:   score,
		URL:         "https://nvd.nist.gov/vuln/detail/" + v.ID,
		Exploits:    exploits,
	}, nil
}

// buildKeyword constructs a search keyword from a scan result.
func buildKeyword(sr models.ScanResult) string {
	parts := []string{}
	if sr.ServiceName != "" {
		parts = append(parts, sr.ServiceName)
	}

	if sr.Banner != "" {
		banner := strings.TrimSpace(sr.Banner)
		if len(banner) > 100 {
			banner = banner[:100]
		}
		parts = append(parts, banner)
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

// queryNVD calls the NVD NIST CVE 2.0 API for a keyword and returns up to 5 CVEs.
func queryNVD(ctx context.Context, client *http.Client, keyword string) ([]CVE, error) {
	apiURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", "5")

	fullURL := apiURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "otnation-platform/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cve: NVD request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cve: NVD API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("cve: failed to read NVD response: %w", err)
	}

	var nvd nvdResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil, fmt.Errorf("cve: failed to parse NVD response: %w", err)
	}

	var cves []CVE
	for _, vuln := range nvd.Vulnerabilities {
		c := vuln.CVE
		desc := ""
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		if desc == "" && len(c.Descriptions) > 0 {
			desc = c.Descriptions[0].Value
		}

		score, severity := extractScore(c.Metrics)
		exploits := extractExploits(c.References)

		cve := CVE{
			ID:          c.ID,
			Description: desc,
			Severity:    severity,
			CVSSScore:   score,
			URL:         "https://nvd.nist.gov/vuln/detail/" + c.ID,
			Exploits:    exploits,
		}
		cves = append(cves, cve)
	}

	return cves, nil
}

type nvdMetrics struct {
	CVSSMetricV31 []struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV31"`
	CVSSMetricV30 []struct {
		CVSSData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV30"`
	CVSSMetricV2 []struct {
		CVSSData struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssData"`
		BaseSeverity string `json:"baseSeverity"`
	} `json:"cvssMetricV2"`
}

func extractScore(m interface{}) (float64, string) {
	b, err := json.Marshal(m)
	if err != nil {
		return 0, "unknown"
	}
	var metrics nvdMetrics
	if err := json.Unmarshal(b, &metrics); err != nil {
		return 0, "unknown"
	}

	if len(metrics.CVSSMetricV31) > 0 {
		d := metrics.CVSSMetricV31[0].CVSSData
		return d.BaseScore, strings.ToLower(d.BaseSeverity)
	}
	if len(metrics.CVSSMetricV30) > 0 {
		d := metrics.CVSSMetricV30[0].CVSSData
		return d.BaseScore, strings.ToLower(d.BaseSeverity)
	}
	if len(metrics.CVSSMetricV2) > 0 {
		d := metrics.CVSSMetricV2[0]
		return d.CVSSData.BaseScore, strings.ToLower(d.BaseSeverity)
	}
	return 0, "unknown"
}

// CVSSSeverity maps a CVSS score to a platform severity level string.
func CVSSSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}
