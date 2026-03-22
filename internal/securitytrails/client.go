// Package securitytrails provides a client for the SecurityTrails REST API.
package securitytrails

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ErrNoData is returned when the primary /v1/domain endpoint returns 404.
var ErrNoData = errors.New("securitytrails: no data for this domain")

// Client is a SecurityTrails REST API client.
type Client struct {
	apiKey string
	http   *http.Client
}

// New creates a new SecurityTrails client with the given API key.
func New(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		http:   &http.Client{Timeout: 60 * time.Second},
	}
}

// EnrichResult aggregates results from all SecurityTrails endpoints for a domain.
type EnrichResult struct {
	Domain       interface{} `json:"domain"`
	HistoryA     interface{} `json:"history_a"`
	HistoryAAAA  interface{} `json:"history_aaaa"`
	HistoryMX    interface{} `json:"history_mx"`
	HistoryNS    interface{} `json:"history_ns"`
	HistoryTXT   interface{} `json:"history_txt"`
	HistoryWhois interface{} `json:"history_whois"`
	FetchedAt    time.Time   `json:"fetched_at"`
}

// fetch performs a GET request to the given URL with the API key header
// and decodes the JSON response into a map. Returns nil on 404.
func (c *Client) fetch(ctx context.Context, url string) (interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("securitytrails: build request: %w", err)
	}
	req.Header.Set("APIKEY", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("securitytrails: http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("securitytrails: invalid API key")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securitytrails: unexpected status %d for url %s", resp.StatusCode, url)
	}

	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("securitytrails: decode response: %w", err)
	}
	return result, nil
}

// Enrich calls all SecurityTrails endpoints concurrently and returns an
// aggregated EnrichResult. If the primary /v1/domain endpoint returns 404,
// ErrNoData is returned. Non-critical endpoint failures set that field to nil.
func (c *Client) Enrich(ctx context.Context, domain string) (*EnrichResult, error) {
	base := "https://api.securitytrails.com/v1"

	type fetchResult struct {
		key   string
		value interface{}
		err   error
	}

	endpoints := []struct {
		key string
		url string
	}{
		{"domain", fmt.Sprintf("%s/domain/%s", base, domain)},
		{"history_a", fmt.Sprintf("%s/history/%s/dns/a", base, domain)},
		{"history_aaaa", fmt.Sprintf("%s/history/%s/dns/aaaa", base, domain)},
		{"history_mx", fmt.Sprintf("%s/history/%s/dns/mx", base, domain)},
		{"history_ns", fmt.Sprintf("%s/history/%s/dns/ns", base, domain)},
		{"history_txt", fmt.Sprintf("%s/history/%s/dns/txt", base, domain)},
		{"history_whois", fmt.Sprintf("%s/history/%s/whois", base, domain)},
	}

	results := make(chan fetchResult, len(endpoints))
	var wg sync.WaitGroup

	for _, ep := range endpoints {
		wg.Add(1)
		go func(key, url string) {
			defer wg.Done()
			val, err := c.fetch(ctx, url)
			results <- fetchResult{key: key, value: val, err: err}
		}(ep.key, ep.url)
	}

	wg.Wait()
	close(results)

	out := &EnrichResult{FetchedAt: time.Now().UTC()}
	for r := range results {
		switch r.key {
		case "domain":
			if r.err != nil {
				return nil, r.err
			}
			if r.value == nil {
				return nil, ErrNoData
			}
			out.Domain = r.value
		case "history_a":
			if r.err == nil {
				out.HistoryA = r.value
			}
		case "history_aaaa":
			if r.err == nil {
				out.HistoryAAAA = r.value
			}
		case "history_mx":
			if r.err == nil {
				out.HistoryMX = r.value
			}
		case "history_ns":
			if r.err == nil {
				out.HistoryNS = r.value
			}
		case "history_txt":
			if r.err == nil {
				out.HistoryTXT = r.value
			}
		case "history_whois":
			if r.err == nil {
				out.HistoryWhois = r.value
			}
		}
	}

	return out, nil
}
