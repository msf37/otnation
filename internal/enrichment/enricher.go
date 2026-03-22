// Package enrichment provides IP geolocation and ASN enrichment via ipapi.co.
package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

// ipapiResponse maps the JSON fields returned by ipapi.co.
type ipapiResponse struct {
	CountryCode string `json:"country_code"`
	ASN         string `json:"asn"`
	Org         string `json:"org"`
}

// EnrichIP fetches geolocation and ASN data for an IP asset and persists it.
func EnrichIP(ctx context.Context, st *store.Store, assetID uuid.UUID, identityID uuid.UUID) error {
	asset, err := st.GetAsset(ctx, assetID)
	if err != nil {
		return fmt.Errorf("enrichment.EnrichIP: load asset %s: %w", assetID, err)
	}

	ip := net.ParseIP(asset.Value)
	if ip == nil {
		// Not a parseable IP — skip enrichment silently.
		log.Debug().Str("value", asset.Value).Msg("enrichment: not an IP, skipping")
		return nil
	}

	priv := isPrivateIP(ip)
	asset.IsPublic = !priv

	if priv {
		// Private IPs don't benefit from external enrichment.
		if _, err := st.UpsertAsset(ctx, asset); err != nil {
			return fmt.Errorf("enrichment.EnrichIP: upsert private asset: %w", err)
		}
		log.Debug().Str("ip", asset.Value).Msg("enrichment: private IP, skipping external lookup")
		return nil
	}

	// Call ipapi.co with a 10-second timeout.
	apiURL := fmt.Sprintf("https://ipapi.co/%s/json/", ip.String())
	httpClient := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return fmt.Errorf("enrichment.EnrichIP: build request: %w", err)
	}
	req.Header.Set("User-Agent", "otnation-platform/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("ip", asset.Value).Msg("enrichment: ipapi.co request failed")
		// Still upsert what we know (IsPublic flag).
		if _, uErr := st.UpsertAsset(ctx, asset); uErr != nil {
			return fmt.Errorf("enrichment.EnrichIP: upsert after failed request: %w", uErr)
		}
		return nil
	}
	defer resp.Body.Close()

	var raw ipapiResponse
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&raw); err != nil {
		log.Warn().Err(err).Str("ip", asset.Value).Msg("enrichment: failed to decode ipapi response")
		if _, uErr := st.UpsertAsset(ctx, asset); uErr != nil {
			return fmt.Errorf("enrichment.EnrichIP: upsert after decode error: %w", uErr)
		}
		return nil
	}

	// Re-encode raw response for storage.
	rawBytes, _ := json.Marshal(raw)

	// Parse ASN: strip leading "AS" and convert to int64.
	if raw.ASN != "" {
		asnStr := strings.TrimPrefix(raw.ASN, "AS")
		if n, err := strconv.ParseInt(asnStr, 10, 64); err == nil {
			asset.ASN = &n
		}
	}
	asset.CountryCode = raw.CountryCode
	asset.ASNOrg = raw.Org

	if _, err := st.UpsertAsset(ctx, asset); err != nil {
		return fmt.Errorf("enrichment.EnrichIP: upsert enriched asset: %w", err)
	}

	// Store enrichment record.
	enr := models.EnrichmentRecord{
		AssetID: assetID,
		Source:  models.EnrichmentSourceInternal,
		Data:    rawBytes,
	}
	if _, err := st.UpsertEnrichment(ctx, enr); err != nil {
		log.Error().Err(err).Str("ip", asset.Value).Msg("enrichment: failed to upsert enrichment record")
	}

	log.Info().
		Str("ip", asset.Value).
		Str("country", raw.CountryCode).
		Str("asn", raw.ASN).
		Str("org", raw.Org).
		Msg("enrichment: IP enriched")

	return nil
}

// isPrivateIP reports whether ip is a private / loopback / link-local address.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
