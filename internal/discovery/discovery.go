// Package discovery orchestrates the initial seeding phase of a discovery run.
// It expands seeds into assets and enqueues downstream jobs for scanning,
// DNS resolution, and enrichment.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

// JobPayload is the canonical payload structure for all background jobs
// created by the discovery orchestrator.
type JobPayload struct {
	RunID      uuid.UUID `json:"run_id"`
	IdentityID uuid.UUID `json:"identity_id"`
	AssetID    uuid.UUID `json:"asset_id,omitempty"`
	Value      string    `json:"value,omitempty"`
}

// RunDiscovery expands all seeds for the given run's identity, upserts assets,
// and enqueues ip_enrich, dns_resolve, and scan jobs.
func RunDiscovery(ctx context.Context, st *store.Store, runID uuid.UUID, identityID uuid.UUID) error {
	// Mark run as running.
	now := time.Now()
	if _, err := st.UpdateRun(ctx, runID, models.RunStatusRunning, &now, nil, nil); err != nil {
		return fmt.Errorf("discovery.RunDiscovery: mark run running: %w", err)
	}

	seeds, err := st.ListSeeds(ctx, identityID)
	if err != nil {
		return fmt.Errorf("discovery.RunDiscovery: list seeds: %w", err)
	}

	for _, seed := range seeds {
		switch seed.Type {
		case models.SeedTypeIP:
			if err := handleIP(ctx, st, runID, identityID, seed.Value); err != nil {
				log.Error().Err(err).Str("ip", seed.Value).Msg("discovery: failed to handle IP seed")
			}

		case models.SeedTypeCIDR:
			if err := handleCIDR(ctx, st, runID, identityID, seed.Value); err != nil {
				log.Error().Err(err).Str("cidr", seed.Value).Msg("discovery: failed to handle CIDR seed")
			}

		case models.SeedTypeDomain:
			if err := handleDomain(ctx, st, runID, identityID, seed.Value); err != nil {
				log.Error().Err(err).Str("domain", seed.Value).Msg("discovery: failed to handle domain seed")
			}

		default:
			log.Warn().Str("type", string(seed.Type)).Str("value", seed.Value).Msg("discovery: unknown seed type")
		}
	}

	// Mark the discovery phase completed (more jobs are still queued).
	if _, err := st.UpdateRun(ctx, runID, models.RunStatusCompleted, &now, nil, nil); err != nil {
		return fmt.Errorf("discovery.RunDiscovery: mark run completed: %w", err)
	}

	log.Info().Str("run_id", runID.String()).Int("seeds", len(seeds)).Msg("discovery: run completed")
	return nil
}

// handleIP upserts a single IP asset and enqueues ip_enrich + scan jobs.
func handleIP(ctx context.Context, st *store.Store, runID, identityID uuid.UUID, ip string) error {
	asset := models.Asset{
		IdentityID: identityID,
		Type:       models.AssetTypeIP,
		Value:      ip,
		Provenance: models.ProvenanceUserInput,
	}
	saved, err := st.UpsertAsset(ctx, asset)
	if err != nil {
		return fmt.Errorf("handleIP upsert: %w", err)
	}

	return enqueueIPJobs(ctx, st, runID, identityID, saved.ID)
}

// handleCIDR expands a CIDR into individual IPs (max 254 for /24 or smaller)
// and enqueues ip_enrich + scan jobs for each.
func handleCIDR(ctx context.Context, st *store.Store, runID, identityID uuid.UUID, cidr string) error {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("handleCIDR parse: %w", err)
	}

	prefix, bits := network.Mask.Size()
	_ = ip
	_ = bits

	// Only enumerate if prefix <= 24 (at most a /24 = 254 hosts).
	if prefix > 24 {
		// Single or very small range — still enumerate.
	}

	var ips []string
	for ip := cloneIP(network.IP); network.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
		if len(ips) >= 256 {
			break
		}
	}

	// Skip network address (first) and broadcast (last) for IPv4.
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	if len(ips) > 254 {
		ips = ips[:254]
	}

	for _, ipStr := range ips {
		asset := models.Asset{
			IdentityID: identityID,
			Type:       models.AssetTypeIP,
			Value:      ipStr,
			Provenance: models.ProvenanceSubnetExpansion,
		}
		saved, err := st.UpsertAsset(ctx, asset)
		if err != nil {
			log.Error().Err(err).Str("ip", ipStr).Msg("discovery: failed to upsert CIDR IP asset")
			continue
		}
		if err := enqueueIPJobs(ctx, st, runID, identityID, saved.ID); err != nil {
			log.Error().Err(err).Str("ip", ipStr).Msg("discovery: failed to enqueue CIDR IP jobs")
		}
	}
	return nil
}

// handleDomain upserts a domain asset and enqueues dns_resolve + scan jobs.
func handleDomain(ctx context.Context, st *store.Store, runID, identityID uuid.UUID, domain string) error {
	asset := models.Asset{
		IdentityID: identityID,
		Type:       models.AssetTypeDomain,
		Value:      domain,
		Provenance: models.ProvenanceUserInput,
	}
	saved, err := st.UpsertAsset(ctx, asset)
	if err != nil {
		return fmt.Errorf("handleDomain upsert: %w", err)
	}

	// dns_resolve job.
	if err := createJob(ctx, st, runID, "dns_resolve", JobPayload{
		RunID:      runID,
		IdentityID: identityID,
		AssetID:    saved.ID,
	}); err != nil {
		return fmt.Errorf("handleDomain dns_resolve job: %w", err)
	}

	// scan job.
	if err := createJob(ctx, st, runID, "scan", JobPayload{
		RunID:      runID,
		IdentityID: identityID,
		AssetID:    saved.ID,
	}); err != nil {
		return fmt.Errorf("handleDomain scan job: %w", err)
	}

	return nil
}

// enqueueIPJobs creates ip_enrich and scan jobs for an IP asset.
func enqueueIPJobs(ctx context.Context, st *store.Store, runID, identityID, assetID uuid.UUID) error {
	if err := createJob(ctx, st, runID, "ip_enrich", JobPayload{
		RunID:      runID,
		IdentityID: identityID,
		AssetID:    assetID,
	}); err != nil {
		return fmt.Errorf("enqueueIPJobs ip_enrich: %w", err)
	}

	if err := createJob(ctx, st, runID, "scan", JobPayload{
		RunID:      runID,
		IdentityID: identityID,
		AssetID:    assetID,
	}); err != nil {
		return fmt.Errorf("enqueueIPJobs scan: %w", err)
	}

	return nil
}

// createJob marshals a payload and inserts a job record.
func createJob(ctx context.Context, st *store.Store, runID uuid.UUID, jobType string, payload JobPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("createJob marshal: %w", err)
	}
	if _, err := st.CreateJob(ctx, runID, jobType, data); err != nil {
		return fmt.Errorf("createJob %s: %w", jobType, err)
	}
	return nil
}

// cloneIP returns a copy of an IP to avoid aliasing during iteration.
func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// incrementIP increments an IP address in-place.
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
