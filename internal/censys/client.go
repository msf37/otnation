// Package censys queries the Censys Search API v2 for host data.
package censys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

var ErrNotFound = errors.New("censys: host not found")

type HostData struct {
	IP       string                   `json:"ip"`
	Services []map[string]interface{} `json:"services"`
	Labels   []string                 `json:"labels,omitempty"`
}

type Client struct {
	APIID      string
	APISecret  string
	HTTPClient *http.Client
}

func NewClient(apiID, apiSecret string) *Client {
	return &Client{
		APIID:     apiID,
		APISecret: apiSecret,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) FetchHost(ctx context.Context, ip string) (*HostData, error) {
	if c.APIID == "" || c.APISecret == "" {
		return nil, errors.New("censys: API credentials not configured")
	}
	url := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	creds := base64.StdEncoding.EncodeToString([]byte(c.APIID + ":" + c.APISecret))
	req.Header.Set("Authorization", "Basic "+creds)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("censys: API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, err
	}

	var wrapper struct {
		Code   int      `json:"code"`
		Result HostData `json:"result"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, err
	}
	return &wrapper.Result, nil
}
