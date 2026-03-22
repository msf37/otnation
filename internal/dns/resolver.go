// Package dns provides DNS resolution and subdomain enumeration for platform assets.
package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

// jobPayload mirrors discovery.JobPayload to avoid an import cycle.
type jobPayload struct {
	RunID      uuid.UUID `json:"run_id"`
	IdentityID uuid.UUID `json:"identity_id"`
	AssetID    uuid.UUID `json:"asset_id,omitempty"`
}

// Resolve performs full DNS resolution for the given domain asset:
//   - A records  (IPv4)
//   - AAAA records (IPv6)
//   - CNAME chain (stores each hop, resolves the final target's IPs)
//   - Subdomain enumeration with A / AAAA / CNAME for each found subdomain
//
// For every newly discovered IP asset, ip_enrich and scan jobs are enqueued.
func Resolve(ctx context.Context, st *store.Store, assetID uuid.UUID, identityID uuid.UUID, runID uuid.UUID) error {
	asset, err := st.GetAsset(ctx, assetID)
	if err != nil {
		return fmt.Errorf("dns.Resolve: load asset %s: %w", assetID, err)
	}

	domain := asset.Value
	log.Info().Str("domain", domain).Msg("dns: resolving")

	if err := resolveFullDomain(ctx, st, domain, assetID, identityID, runID); err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("dns: resolution errors (non-fatal)")
	}

	// Subdomain enumeration.
	for _, prefix := range commonSubdomains {
		sub := prefix + "." + domain

		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, sub)
		if err != nil {
			continue // subdomain does not exist
		}
		if len(addrs) == 0 {
			continue
		}

		subAsset := models.Asset{
			IdentityID: identityID,
			Type:       models.AssetTypeSubdomain,
			Value:      sub,
			Provenance: models.ProvenanceDNS,
		}
		savedSub, err := st.UpsertAsset(ctx, subAsset)
		if err != nil {
			log.Error().Err(err).Str("subdomain", sub).Msg("dns: failed to upsert subdomain asset")
			continue
		}

		log.Info().Str("subdomain", sub).Int("ips", len(addrs)).Msg("dns: subdomain found")

		if err := resolveFullDomain(ctx, st, sub, savedSub.ID, identityID, runID); err != nil {
			log.Warn().Err(err).Str("subdomain", sub).Msg("dns: subdomain resolution errors (non-fatal)")
		}
	}

	return nil
}

// enumerateConcurrency is the number of parallel DNS probes during on-demand enumeration.
const enumerateConcurrency = 50

// EnumerateSubdomains runs subdomain brute-force against the given domain asset,
// upserts any discovered subdomain and IP assets, and returns the full list of
// subdomain assets found. Unlike Resolve it does not require a run and does not
// enqueue any background jobs — it is meant for on-demand use from the UI.
//
// Lookups are performed concurrently (up to enumerateConcurrency goroutines) so
// the full wordlist completes in seconds rather than minutes.
func EnumerateSubdomains(ctx context.Context, st *store.Store, assetID uuid.UUID, identityID uuid.UUID) ([]models.Asset, error) {
	asset, err := st.GetAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("dns.EnumerateSubdomains: load asset: %w", err)
	}
	domain := asset.Value
	log.Info().Str("domain", domain).Int("wordlist", len(commonSubdomains)).Msg("dns: on-demand subdomain enumeration started")

	sem := make(chan struct{}, enumerateConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var found []models.Asset

	for _, p := range commonSubdomains {
		if ctx.Err() != nil {
			break
		}
		prefix := p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Interface("panic", r).Str("subdomain", prefix+"."+domain).Msg("dns: goroutine panic recovered")
				}
			}()

			sub := prefix + "." + domain
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, sub)
			if err != nil || len(addrs) == 0 {
				return
			}

			subAsset := models.Asset{
				IdentityID: identityID,
				Type:       models.AssetTypeSubdomain,
				Value:      sub,
				Provenance: models.ProvenanceDNS,
			}
			savedSub, err := st.UpsertAsset(ctx, subAsset)
			if err != nil {
				log.Error().Err(err).Str("subdomain", sub).Msg("dns: failed to upsert subdomain asset")
				return
			}
			log.Info().Str("subdomain", sub).Int("ips", len(addrs)).Msg("dns: subdomain found")
			resolveRecordsOnly(ctx, st, sub, savedSub.ID, identityID)

			mu.Lock()
			found = append(found, savedSub)
			mu.Unlock()
		}()
	}

	wg.Wait()
	log.Info().Str("domain", domain).Int("found", len(found)).Msg("dns: on-demand enumeration complete")
	return found, nil
}

// resolveRecordsOnly resolves A, AAAA, and CNAME records and stores them along
// with the corresponding IP assets. It does NOT enqueue any background jobs.
func resolveRecordsOnly(ctx context.Context, st *store.Store, name string, assetID uuid.UUID, identityID uuid.UUID) {
	// CNAME
	if cname, err := net.LookupCNAME(name); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && cname != name {
			rec := models.DNSRecord{IdentityID: identityID, AssetID: assetID, RecordType: "CNAME", Name: name, Value: cname}
			if _, err := st.InsertDNSRecord(ctx, rec); err != nil {
				log.Error().Err(err).Str("name", name).Msg("dns: failed to insert CNAME")
			}
		}
	}
	// A records
	for _, ip := range mustLookupIP(ctx, name, "ip4") {
		h := ip.String()
		rec := models.DNSRecord{IdentityID: identityID, AssetID: assetID, RecordType: "A", Name: name, Value: h, ResolvedIP: h}
		if _, err := st.InsertDNSRecord(ctx, rec); err != nil {
			log.Error().Err(err).Str("name", name).Str("ip", h).Msg("dns: failed to insert A record")
		}
		upsertIPOnly(ctx, st, h, identityID)
	}
	// AAAA records
	for _, ip := range mustLookupIP(ctx, name, "ip6") {
		h := ip.String()
		rec := models.DNSRecord{IdentityID: identityID, AssetID: assetID, RecordType: "AAAA", Name: name, Value: h, ResolvedIP: h}
		if _, err := st.InsertDNSRecord(ctx, rec); err != nil {
			log.Error().Err(err).Str("name", name).Str("ip", h).Msg("dns: failed to insert AAAA record")
		}
		upsertIPOnly(ctx, st, h, identityID)
	}
}

func mustLookupIP(ctx context.Context, name, network string) []net.IP {
	addrs, _ := net.DefaultResolver.LookupIP(ctx, network, name)
	return addrs
}

func upsertIPOnly(ctx context.Context, st *store.Store, ip string, identityID uuid.UUID) {
	a := models.Asset{IdentityID: identityID, Type: models.AssetTypeIP, Value: ip, Provenance: models.ProvenanceDNS}
	if _, err := st.UpsertAsset(ctx, a); err != nil {
		log.Error().Err(err).Str("ip", ip).Msg("dns: failed to upsert IP asset")
	}
}

// resolveFullDomain resolves A, AAAA, and CNAME records for a single name,
// stores all dns_records, upserts IP assets, and enqueues downstream jobs.
func resolveFullDomain(ctx context.Context, st *store.Store, name string, assetID uuid.UUID, identityID uuid.UUID, runID uuid.UUID) error {
	// -----------------------------------------------------------------------
	// CNAME chain — must be checked before A/AAAA so we capture intermediate
	// hops. net.LookupCNAME follows the full chain and returns the final FQDN.
	// -----------------------------------------------------------------------
	cname, err := net.LookupCNAME(name)
	if err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && cname != name {
			rec := models.DNSRecord{
				IdentityID: identityID,
				AssetID:    assetID,
				RecordType: "CNAME",
				Name:       name,
				Value:      cname,
			}
			if _, err := st.InsertDNSRecord(ctx, rec); err != nil {
				log.Error().Err(err).Str("name", name).Str("cname", cname).Msg("dns: failed to insert CNAME record")
			} else {
				log.Debug().Str("name", name).Str("cname", cname).Msg("dns: CNAME stored")
			}
		}
	}

	// -----------------------------------------------------------------------
	// A records (IPv4) — explicit lookup via LookupIP with "ip4" network.
	// -----------------------------------------------------------------------
	ipv4Addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
	if err != nil {
		log.Debug().Err(err).Str("name", name).Msg("dns: no A records")
	}
	for _, ip := range ipv4Addrs {
		h := ip.String()
		rec := models.DNSRecord{
			IdentityID: identityID,
			AssetID:    assetID,
			RecordType: "A",
			Name:       name,
			Value:      h,
			ResolvedIP: h,
		}
		if _, err := st.InsertDNSRecord(ctx, rec); err != nil {
			log.Error().Err(err).Str("name", name).Str("ip", h).Msg("dns: failed to insert A record")
		}
		if err := upsertIPAndEnqueue(ctx, st, h, identityID, runID); err != nil {
			log.Error().Err(err).Str("ip", h).Msg("dns: failed to enqueue jobs for A record IP")
		}
	}

	// -----------------------------------------------------------------------
	// AAAA records (IPv6) — explicit lookup via LookupIP with "ip6" network.
	// -----------------------------------------------------------------------
	ipv6Addrs, err := net.DefaultResolver.LookupIP(ctx, "ip6", name)
	if err != nil {
		log.Debug().Err(err).Str("name", name).Msg("dns: no AAAA records")
	}
	for _, ip := range ipv6Addrs {
		h := ip.String()
		rec := models.DNSRecord{
			IdentityID: identityID,
			AssetID:    assetID,
			RecordType: "AAAA",
			Name:       name,
			Value:      h,
			ResolvedIP: h,
		}
		if _, err := st.InsertDNSRecord(ctx, rec); err != nil {
			log.Error().Err(err).Str("name", name).Str("ip", h).Msg("dns: failed to insert AAAA record")
		}
		if err := upsertIPAndEnqueue(ctx, st, h, identityID, runID); err != nil {
			log.Error().Err(err).Str("ip", h).Msg("dns: failed to enqueue jobs for AAAA record IP")
		}
	}

	total := len(ipv4Addrs) + len(ipv6Addrs)
	log.Info().
		Str("name", name).
		Int("a_records", len(ipv4Addrs)).
		Int("aaaa_records", len(ipv6Addrs)).
		Msg("dns: resolution complete")

	if total == 0 && err != nil {
		return fmt.Errorf("no A or AAAA records resolved for %s", name)
	}
	return nil
}

// upsertIPAndEnqueue creates (or finds) an IP asset and enqueues ip_enrich + scan jobs.
func upsertIPAndEnqueue(ctx context.Context, st *store.Store, ip string, identityID uuid.UUID, runID uuid.UUID) error {
	ipAsset := models.Asset{
		IdentityID: identityID,
		Type:       models.AssetTypeIP,
		Value:      ip,
		Provenance: models.ProvenanceDNS,
	}
	saved, err := st.UpsertAsset(ctx, ipAsset)
	if err != nil {
		return fmt.Errorf("upsert IP asset: %w", err)
	}

	for _, jobType := range []string{"ip_enrich", "scan"} {
		p := jobPayload{RunID: runID, IdentityID: identityID, AssetID: saved.ID}
		data, _ := json.Marshal(p)
		if _, err := st.CreateJob(ctx, runID, jobType, data); err != nil {
			log.Error().Err(err).Str("job", jobType).Str("ip", ip).Msg("dns: failed to enqueue job")
		}
	}
	return nil
}
