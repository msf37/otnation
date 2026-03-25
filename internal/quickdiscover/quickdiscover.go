// Package quickdiscover provides on-demand, single-asset neighbourhood
// discovery triggered from the graph UI.
//
// For an IP asset  – probe the /24 subnet on common ports, record all
// responsive hosts as assets, store open-port scan results, and perform
// reverse-DNS on each live host.
//
// For a domain/subdomain asset – run subdomain brute-force enumeration
// (delegates to the dns package) and resolve A/AAAA records for each found
// subdomain.
package quickdiscover

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/otnation/platform/internal/banner"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

const (
	probeTimeout     = 1200 * time.Millisecond
	probeConcurrency = 60
)

// probePorts are checked for every candidate IP in the subnet.
var probePorts = []int{22, 80, 443, 8080, 8443}

// cloudOrgPatterns are case-insensitive substrings matched against
// asset.ASNOrg to identify cloud providers and CDNs whose /24 subnets
// belong entirely to the provider — not the target organisation.
var cloudOrgPatterns = []string{
	"amazon", "aws",
	"cloudflare",
	"akamai", "akamai technologies",
	"fastly",
	"microsoft", "azure",
	"google", "google cloud",
	"digitalocean",
	"linode",
	"vultr", "choopa",
	"ovh",
	"hetzner",
	"leaseweb",
	"rackspace",
	"cdn77",
	"stackpath",
	"imperva", "incapsula",
	"sucuri",
	"zscaler",
	"alibaba", "aliyun",
	"tencent cloud",
	"oracle cloud",
	"ibm cloud", "softlayer",
}

// rdnsCloudPatterns are substrings matched against the reverse-DNS hostname
// to detect cloud / CDN IPs when ASN enrichment is not yet available.
var rdnsCloudPatterns = []string{
	"amazonaws.com",
	"compute.internal",
	"googleusercontent.com",
	"cloud.google.com",
	"azure.com",
	"cloudapp.net",
	"cloudapp.azure.com",
	"windows.net",
	"cloudflare.com",
	"fastly.net",
	"akamaiedge.net",
	"akadns.net",
	"akamaihd.net",
	"edgekey.net",
	"edgesuite.net",
	"digitalocean.com",
	"linode.com",
	"vultr.com",
	"choopa.net",
	"ovh.net",
	"hetzner.com",
	"hetzner.de",
}

// isEC2Instance returns true when the reverse-DNS hostname indicates an AWS
// EC2 instance (e.g. ec2-1-2-3-4.region.compute.amazonaws.com).
// EC2 instances are target-controlled compute — subnet scanning is allowed.
func isEC2Instance(asset models.Asset) bool {
	rdns := strings.ToLower(asset.ReverseDNS)
	return strings.HasPrefix(rdns, "ec2-") && strings.Contains(rdns, ".compute.amazonaws.com")
}

// isCloudOrCDN returns true when the asset's ASN org, cloud flag, or
// reverse-DNS hostname indicate the IP belongs to shared cloud/CDN infrastructure.
// EC2 instances are explicitly excluded — they are target-controlled and their
// subnet is worth scanning.
func isCloudOrCDN(asset models.Asset) bool {
	// EC2 takes priority: even though it's AWS, it's target-owned compute.
	if isEC2Instance(asset) {
		return false
	}
	if asset.IsCloud {
		return true
	}
	if asset.ASNOrg != "" {
		org := strings.ToLower(asset.ASNOrg)
		for _, pat := range cloudOrgPatterns {
			if strings.Contains(org, pat) {
				return true
			}
		}
	}
	// Fallback: check reverse DNS when enrichment hasn't run yet.
	if asset.ReverseDNS != "" {
		rdns := strings.ToLower(asset.ReverseDNS)
		for _, pat := range rdnsCloudPatterns {
			if strings.Contains(rdns, pat) {
				return true
			}
		}
	}
	return false
}

// openPort holds the result of a single successful TCP probe.
type openPort struct {
	port   int
	banner string
}

// Result is returned to the caller with a summary of what was found.
type Result struct {
	NewAssets  []models.Asset `json:"new_assets"`
	DNSLinks   []DNSLink      `json:"dns_links"`
	Subdomains []models.Asset `json:"subdomains,omitempty"`
	Message    string         `json:"message"`
}

// DNSLink captures a reverse-DNS hit: IP → hostname.
type DNSLink struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// DiscoverFromIP derives the /24 subnet of the given IP asset, probes every
// host on common ports, saves live hosts as assets with their open port scan
// results, and performs reverse-DNS on all checked IPs.
//
// If the IP belongs to a cloud provider or CDN the subnet scan is skipped —
// only the single IP itself is probed and added.
func DiscoverFromIP(ctx context.Context, st *store.Store, asset models.Asset) (*Result, error) {
	ip := net.ParseIP(asset.Value)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", asset.Value)
	}
	ip = ip.To4()
	if ip == nil {
		return discoverIPv6(ctx, st, asset)
	}

	// Populate reverse DNS on the asset struct if not already set — this lets
	// isCloudOrCDN detect cloud IPs even before Shodan enrichment has run.
	if asset.ReverseDNS == "" {
		if names, err := net.LookupAddr(asset.Value); err == nil && len(names) > 0 {
			asset.ReverseDNS = strings.TrimSuffix(names[0], ".")
		}
	}

	if isCloudOrCDN(asset) {
		log.Info().
			Str("asset", asset.Value).
			Str("asn_org", asset.ASNOrg).
			Str("rdns", asset.ReverseDNS).
			Bool("is_cloud", asset.IsCloud).
			Msg("quickdiscover: cloud/CDN IP — skipping subnet, probing single host only")
		return discoverSingleIP(ctx, st, asset)
	}

	if isEC2Instance(asset) {
		log.Info().
			Str("asset", asset.Value).
			Str("rdns", asset.ReverseDNS).
			Msg("quickdiscover: EC2 instance — treating as target-controlled, scanning subnet")
	}

	subnet := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
	_, network, _ := net.ParseCIDR(subnet)

	var candidates []string
	for h := cloneIP(network.IP); network.Contains(h); incrementIP(h) {
		candidates = append(candidates, h.String())
	}
	if len(candidates) > 2 {
		candidates = candidates[1 : len(candidates)-1] // drop .0 and .255
	}

	log.Info().
		Str("asset", asset.Value).
		Str("subnet", subnet).
		Int("hosts", len(candidates)).
		Msg("quickdiscover: subnet probe started")

	type probeResult struct {
		ip        string
		openPorts []openPort
		rdns      string
		newAsset  *models.Asset
	}

	results := make([]probeResult, len(candidates))
	sem := make(chan struct{}, probeConcurrency)
	var wg sync.WaitGroup

	for i, candidate := range candidates {
		idx := i
		host := candidate
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			openPorts := probeAllPorts(host, probePorts, probeTimeout)
			if len(openPorts) == 0 {
				return
			}

			pr := probeResult{ip: host, openPorts: openPorts}

			// Reverse DNS.
			if names, err := net.LookupAddr(host); err == nil && len(names) > 0 {
				pr.rdns = strings.TrimSuffix(names[0], ".")
			}

			// Upsert the IP as an asset.
			a := models.Asset{
				IdentityID: asset.IdentityID,
				Type:       models.AssetTypeIP,
				Value:      host,
				Provenance: models.ProvenanceSubnetExpansion,
				ReverseDNS: pr.rdns,
			}
			saved, err := st.UpsertAsset(ctx, a)
			if err != nil {
				log.Error().Err(err).Str("ip", host).Msg("quickdiscover: failed to upsert IP")
				return
			}
			pr.newAsset = &saved

			// Persist a ScanResult for every open port found.
			for _, op := range openPorts {
				cls := banner.Classify(op.port, op.banner)
				sr := models.ScanResult{
					AssetID:         saved.ID,
					IdentityID:      asset.IdentityID,
					Port:            op.port,
					Protocol:        "tcp",
					ServiceName:     cls.ServiceName,
					Banner:          op.banner,
					ServiceCategory: cls.Category,
					Confidence:      cls.Confidence,
					RawResponse:     []byte(op.banner),
					ScannedAt:       time.Now(),
				}
				if _, err := st.InsertScanResult(ctx, sr); err != nil {
					log.Debug().Err(err).Str("ip", host).Int("port", op.port).
						Msg("quickdiscover: scan result insert skipped (dup?)")
				}
			}

			// Store reverse-DNS record if we found one.
			if pr.rdns != "" {
				rec := models.DNSRecord{
					IdentityID: asset.IdentityID,
					AssetID:    saved.ID,
					RecordType: "PTR",
					Name:       host,
					Value:      pr.rdns,
				}
				if _, err := st.InsertDNSRecord(ctx, rec); err != nil {
					log.Debug().Err(err).Str("ip", host).Msg("quickdiscover: PTR insert skipped (dup?)")
				}
			}

			results[idx] = pr
		}()
	}
	wg.Wait()

	res := &Result{}
	seenID := make(map[uuid.UUID]bool)
	seenID[asset.ID] = true // don't re-report the source asset

	for _, pr := range results {
		if len(pr.openPorts) == 0 || pr.newAsset == nil {
			continue
		}
		if !seenID[pr.newAsset.ID] {
			seenID[pr.newAsset.ID] = true
			res.NewAssets = append(res.NewAssets, *pr.newAsset)
		}
		if pr.rdns != "" {
			res.DNSLinks = append(res.DNSLinks, DNSLink{IP: pr.ip, Hostname: pr.rdns})
		}
	}

	res.Message = fmt.Sprintf("Probed %d hosts in %s — found %d live, %d with rDNS",
		len(candidates), subnet, len(res.NewAssets), len(res.DNSLinks))

	log.Info().
		Str("subnet", subnet).
		Int("live", len(res.NewAssets)).
		Msg("quickdiscover: subnet probe complete")

	return res, nil
}

// DiscoverFromDomain runs subdomain enumeration for a domain/subdomain asset.
func DiscoverFromDomain(ctx context.Context, st *store.Store, asset models.Asset,
	enumerateFn func(ctx context.Context, st *store.Store, assetID uuid.UUID, identityID uuid.UUID) ([]models.Asset, error),
) (*Result, error) {
	subs, err := enumerateFn(ctx, st, asset.ID, asset.IdentityID)
	if err != nil {
		return nil, err
	}
	if subs == nil {
		subs = []models.Asset{}
	}
	return &Result{
		Subdomains: subs,
		Message:    fmt.Sprintf("Subdomain enumeration complete — found %d subdomains", len(subs)),
	}, nil
}

// discoverSingleIP probes only the asset's own IP (used for cloud/CDN addresses
// where scanning the /24 subnet would hit infrastructure owned by the provider).
func discoverSingleIP(ctx context.Context, st *store.Store, asset models.Asset) (*Result, error) {
	res := &Result{}

	openPorts := probeAllPorts(asset.Value, probePorts, probeTimeout)

	for _, op := range openPorts {
		cls := banner.Classify(op.port, op.banner)
		sr := models.ScanResult{
			AssetID:         asset.ID,
			IdentityID:      asset.IdentityID,
			Port:            op.port,
			Protocol:        "tcp",
			ServiceName:     cls.ServiceName,
			Banner:          op.banner,
			ServiceCategory: cls.Category,
			Confidence:      cls.Confidence,
			RawResponse:     []byte(op.banner),
			ScannedAt:       time.Now(),
		}
		if _, err := st.InsertScanResult(ctx, sr); err != nil {
			log.Debug().Err(err).Str("ip", asset.Value).Int("port", op.port).
				Msg("quickdiscover: single-host scan result skipped (dup?)")
		}
	}

	// Reverse DNS.
	if names, err := net.LookupAddr(asset.Value); err == nil && len(names) > 0 {
		hostname := strings.TrimSuffix(names[0], ".")
		res.DNSLinks = append(res.DNSLinks, DNSLink{IP: asset.Value, Hostname: hostname})
		rec := models.DNSRecord{
			IdentityID: asset.IdentityID,
			AssetID:    asset.ID,
			RecordType: "PTR",
			Name:       asset.Value,
			Value:      hostname,
		}
		if _, err := st.InsertDNSRecord(ctx, rec); err != nil {
			log.Debug().Err(err).Str("ip", asset.Value).Msg("quickdiscover: PTR insert skipped (dup?)")
		}
	}

	ports := make([]int, len(openPorts))
	for i, op := range openPorts { ports[i] = op.port }

	provider := asset.ASNOrg
	if provider == "" {
		provider = "cloud/CDN"
	}
	res.Message = fmt.Sprintf("Cloud/CDN IP (%s) — subnet scan skipped; probed single host, found %d open port(s)",
		provider, len(openPorts))

	return res, nil
}

// discoverIPv6 handles the IPv6 case: reverse-DNS the single host and probe its ports.
func discoverIPv6(ctx context.Context, st *store.Store, asset models.Asset) (*Result, error) {
	res := &Result{Message: "IPv6 asset — subnet scan skipped, port probe + reverse DNS only"}

	openPorts := probeAllPorts(asset.Value, probePorts, probeTimeout)

	for _, op := range openPorts {
		cls := banner.Classify(op.port, op.banner)
		sr := models.ScanResult{
			AssetID:         asset.ID,
			IdentityID:      asset.IdentityID,
			Port:            op.port,
			Protocol:        "tcp",
			ServiceName:     cls.ServiceName,
			Banner:          op.banner,
			ServiceCategory: cls.Category,
			Confidence:      cls.Confidence,
			RawResponse:     []byte(op.banner),
			ScannedAt:       time.Now(),
		}
		if _, err := st.InsertScanResult(ctx, sr); err != nil {
			log.Debug().Err(err).Str("ip", asset.Value).Int("port", op.port).
				Msg("quickdiscover: IPv6 scan result skipped (dup?)")
		}
	}

	if names, err := net.LookupAddr(asset.Value); err == nil && len(names) > 0 {
		hostname := strings.TrimSuffix(names[0], ".")
		res.DNSLinks = append(res.DNSLinks, DNSLink{IP: asset.Value, Hostname: hostname})
		rec := models.DNSRecord{
			IdentityID: asset.IdentityID,
			AssetID:    asset.ID,
			RecordType: "PTR",
			Name:       asset.Value,
			Value:      hostname,
		}
		if _, err := st.InsertDNSRecord(ctx, rec); err != nil {
			log.Debug().Err(err).Msg("quickdiscover: IPv6 PTR insert skipped")
		}
	}
	return res, nil
}

// probeAllPorts attempts a TCP connection to each port. For every port that
// responds it grabs a short banner and returns the full list of open ports.
func probeAllPorts(host string, ports []int, timeout time.Duration) []openPort {
	var open []openPort
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			continue
		}
		// Attempt a quick banner read (non-fatal if nothing comes back).
		var bannerStr string
		conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond)) //nolint:errcheck
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			bannerStr = string(buf[:n])
		}
		conn.Close()
		open = append(open, openPort{port: port, banner: bannerStr})
	}
	return open
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
