// Package crtsh provides a client for the crt.sh Certificate Transparency search API.
package crtsh

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Entry represents a single certificate entry returned by crt.sh.
type Entry struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

// Result holds the aggregated crt.sh search result for a domain.
type Result struct {
	Domain    string    `json:"domain"`
	Entries   []Entry   `json:"entries"`
	Names     []string  `json:"names"` // deduplicated hostnames
	FetchedAt time.Time `json:"fetched_at"`
}

// ErrNoData is returned when no certificates are found for the given domain.
var ErrNoData = fmt.Errorf("crtsh: no certificates found")

var httpClient = &http.Client{Timeout: 30 * time.Second}

// Search queries crt.sh for all certificates related to domain (both wildcard
// subdomains and the domain itself), deduplicates the discovered names, and
// returns a Result. Returns ErrNoData if no certificates are found.
func Search(ctx context.Context, domain string) (*Result, error) {
	// Query for *.domain (subdomains) and domain itself.
	queries := []string{
		"%25." + domain, // %25 is URL-encoded %  → %.domain wildcard
		domain,
	}

	seen := make(map[string]struct{})
	var allEntries []Entry

	for _, q := range queries {
		entries, err := fetchEntries(ctx, q)
		if err != nil {
			// non-fatal — try the next query
			continue
		}
		allEntries = append(allEntries, entries...)
	}

	if len(allEntries) == 0 {
		return nil, ErrNoData
	}

	// Deduplicate names from NameValue (may contain multiple names separated by newlines).
	for _, e := range allEntries {
		for _, raw := range strings.Split(e.NameValue, "\n") {
			name := strings.TrimSpace(raw)
			name = strings.TrimPrefix(name, "*.")
			name = strings.ToLower(name)
			if name == "" {
				continue
			}
			// Only keep names that equal domain or end with .domain.
			if name != domain && !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if _, exists := seen[name]; !exists {
				seen[name] = struct{}{}
			}
		}
	}

	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)

	return &Result{
		Domain:    domain,
		Entries:   allEntries,
		Names:     names,
		FetchedAt: time.Now().UTC(),
	}, nil
}

// fetchEntries performs a single crt.sh JSON query and returns parsed entries.
func fetchEntries(ctx context.Context, query string) ([]Entry, error) {
	rawURL := "https://crt.sh/?q=" + url.QueryEscape(query) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("crtsh: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crtsh: http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crtsh: unexpected status %d for query %s", resp.StatusCode, query)
	}

	var entries []Entry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crtsh: decode response: %w", err)
	}
	return entries, nil
}
