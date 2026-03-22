// Package scanner provides TCP port scanning with banner grabbing and
// service classification for SCADA/ICS assets.
package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/otnation/platform/internal/banner"
	"github.com/otnation/platform/internal/config"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

// ScanAsset performs a TCP port scan of the asset identified by assetID,
// grabs service banners, classifies services, and stores scan results.
func ScanAsset(ctx context.Context, st *store.Store, cfg *config.Config, assetID uuid.UUID, identityID uuid.UUID, runID uuid.UUID) error {
	asset, err := st.GetAsset(ctx, assetID)
	if err != nil {
		return fmt.Errorf("scanner.ScanAsset: load asset %s: %w", assetID, err)
	}

	ports := portList(cfg)

	// Rate limiting interval between port scans.
	var rateInterval time.Duration
	if cfg.Scanner.RateLimitPerSec > 0 {
		rateInterval = time.Second / time.Duration(cfg.Scanner.RateLimitPerSec)
	}

	timeout := time.Duration(cfg.Scanner.TimeoutMS) * time.Millisecond

	for i, port := range ports {
		if i > 0 && rateInterval > 0 {
			time.Sleep(rateInterval)
		}

		// Check context cancellation.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		address := fmt.Sprintf("%s:%d", asset.Value, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			// Port closed or filtered — skip, no result stored.
			continue
		}

		// Banner grab.
		var bannerBytes []byte
		conn.SetReadDeadline(time.Now().Add(timeout)) //nolint:errcheck
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		if n > 0 {
			bannerBytes = buf[:n]
		}
		conn.Close()

		cls := banner.Classify(port, string(bannerBytes))

		result := models.ScanResult{
			AssetID:         assetID,
			IdentityID:      identityID,
			Port:            port,
			Protocol:        "tcp",
			ServiceName:     cls.ServiceName,
			Banner:          string(bannerBytes),
			ServiceCategory: cls.Category,
			Confidence:      cls.Confidence,
			RawResponse:     bannerBytes,
			ScannedAt:       time.Now(),
		}

		if _, err := st.InsertScanResult(ctx, result); err != nil {
			log.Error().Err(err).
				Str("asset_id", assetID.String()).
				Int("port", port).
				Msg("scanner: failed to insert scan result")
			continue
		}

		log.Info().
			Str("asset", asset.Value).
			Int("port", port).
			Str("service", cls.ServiceName).
			Str("category", cls.Category).
			Float64("confidence", cls.Confidence).
			Msg("scanner: open port found")
	}

	return nil
}

// portList returns the list of ports to scan based on cfg.Scanner.DefaultProfile.
func portList(cfg *config.Config) []int {
	scada := cfg.Scanner.SCADAPorts
	switch cfg.Scanner.DefaultProfile {
	case "light":
		if len(scada) >= 6 {
			return scada[:6]
		}
		return scada
	case "deep":
		extra := []int{21, 22, 23, 25, 80, 443, 3389, 5900, 8080, 8443}
		combined := make([]int, 0, len(scada)+len(extra))
		combined = append(combined, scada...)
		combined = append(combined, extra...)
		return combined
	default: // "standard"
		return scada
	}
}
