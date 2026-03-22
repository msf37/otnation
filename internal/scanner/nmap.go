// Package scanner provides nmap-based port scanning with service/version detection.
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	gonmap "github.com/Ullaakut/nmap/v3"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/otnation/platform/internal/banner"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

// NmapScanProfile controls the aggressiveness of the nmap scan.
type NmapScanProfile string

const (
	NmapProfileLight    NmapScanProfile = "light"
	NmapProfileStandard NmapScanProfile = "standard"
	NmapProfileDeep     NmapScanProfile = "deep"
)

// NmapResult is the structured response returned to the API / UI after a scan.
type NmapResult struct {
	Asset       models.Asset        `json:"asset"`
	ScanResults []models.ScanResult `json:"scan_results"`
	Findings    []models.Finding    `json:"findings"`
	RawSummary  NmapSummary         `json:"summary"`
}

// NmapSummary holds high-level nmap run metadata.
type NmapSummary struct {
	Profile      string    `json:"profile"`
	PortsScanned int       `json:"ports_scanned"`
	OpenPorts    int       `json:"open_ports"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	Duration     string    `json:"duration"`
	NmapVersion  string    `json:"nmap_version"`
}

// NmapScanAsset runs nmap against the IP asset, stores results and returns
// a NmapResult with every discovered port, service, version, and banner.
func NmapScanAsset(ctx context.Context, st *store.Store, assetID uuid.UUID, identityID uuid.UUID, profile NmapScanProfile) (*NmapResult, error) {
	asset, err := st.GetAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("nmap: load asset: %w", err)
	}

	ip := asset.Value
	startedAt := time.Now()

	// Build nmap options based on profile.
	opts, portSpec := buildNmapOptions(ip, profile)

	log.Info().
		Str("ip", ip).
		Str("profile", string(profile)).
		Str("ports", portSpec).
		Msg("nmap: starting scan")

	// Convert []func(*gonmap.Scanner) to []gonmap.Option.
	nmapOpts := make([]gonmap.Option, len(opts))
	for i, o := range opts {
		nmapOpts[i] = o
	}

	scanner, err := gonmap.NewScanner(ctx, nmapOpts...)
	if err != nil {
		return nil, fmt.Errorf("nmap: create scanner: %w", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("nmap: run failed: %w", err)
	}
	if len(*warnings) > 0 {
		for _, w := range *warnings {
			log.Warn().Str("ip", ip).Str("warning", w).Msg("nmap: warning")
		}
	}

	finishedAt := time.Now()

	var savedResults []models.ScanResult
	openCount := 0

	for _, host := range result.Hosts {
		if len(host.Ports) == 0 {
			continue
		}
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			openCount++

			svc := port.Service
			transport := string(port.Protocol)
			if transport == "" {
				transport = "tcp"
			}

			// Build service name: prefer nmap detection, fall back to banner classifier.
			serviceName := svc.Name
			if svc.Product != "" {
				serviceName = svc.Product
			}

			// Build a rich banner string combining all nmap service fields.
			bannerStr := buildBanner(svc)

			// Classify using our banner rules (fills category + confidence).
			cls := banner.Classify(int(port.ID), bannerStr)
			if serviceName == "" {
				serviceName = cls.ServiceName
			}

			// Build full evidence JSON.
			evidence := map[string]interface{}{
				"nmap_service": svc.Name,
				"product":      svc.Product,
				"version":      svc.Version,
				"extra_info":   svc.ExtraInfo,
				"device_type":  svc.DeviceType,
				"os_type":      svc.OSType,
				"hostname":     svc.Hostname,
				"cpe":          svc.CPEs,
				"method":       svc.Method,
				"conf":         svc.Confidence,
				"tunnel":       svc.Tunnel,
			}
			// Grab raw banner from script outputs (e.g. banner.nse).
			for _, script := range port.Scripts {
				if script.ID == "banner" || script.ID == "http-title" || script.ID == "ssl-cert" {
					evidence[script.ID] = script.Output
					if script.ID == "banner" && bannerStr == "" {
						bannerStr = script.Output
					}
				}
			}
			evidenceBytes, _ := json.Marshal(evidence)

			sr := models.ScanResult{
				AssetID:         assetID,
				IdentityID:      identityID,
				Port:            int(port.ID),
				Protocol:        transport,
				ServiceName:     serviceName,
				Banner:          bannerStr,
				ServiceCategory: cls.Category,
				Confidence:      cls.Confidence,
				RawResponse:     evidenceBytes,
				ScannedAt:       startedAt,
			}

			saved, err := st.InsertScanResult(ctx, sr)
			if err != nil {
				log.Error().Err(err).Int("port", int(port.ID)).Msg("nmap: failed to save scan result")
				continue
			}
			savedResults = append(savedResults, saved)
			log.Info().
				Str("ip", ip).
				Int("port", int(port.ID)).
				Str("service", serviceName).
				Str("version", svc.Version).
				Msg("nmap: open port found")
		}
	}

	// Reload updated asset and findings.
	updatedAsset, _ := st.GetAsset(ctx, assetID)
	findings, _ := st.ListFindings(ctx, store.FindingFilters{AssetID: &assetID})

	summary := NmapSummary{
		Profile:      string(profile),
		PortsScanned: portCount(portSpec),
		OpenPorts:    openCount,
		StartedAt:    startedAt,
		FinishedAt:   finishedAt,
		Duration:     finishedAt.Sub(startedAt).Round(time.Second).String(),
	}
	if true {
		summary.NmapVersion = result.Scanner
	}

	log.Info().
		Str("ip", ip).
		Int("open_ports", openCount).
		Str("duration", summary.Duration).
		Msg("nmap: scan complete")

	return &NmapResult{
		Asset:       updatedAsset,
		ScanResults: savedResults,
		Findings:    findings,
		RawSummary:  summary,
	}, nil
}

// buildNmapOptions returns nmap scanner options for the given profile.
func buildNmapOptions(ip string, profile NmapScanProfile) ([]func(*gonmap.Scanner), string) {
	// SCADA-focused ports common to all profiles.
	scadaPorts := "21,22,23,25,80,102,443,502,1911,2404,3389,4000,4840,5900,8080,8443,9600,20000,20547,38400,44818,47808"

	switch profile {
	case NmapProfileLight:
		ports := "22,80,102,443,502,1911,2404,3389,4840,20000,44818,47808"
		return []func(*gonmap.Scanner){
			gonmap.WithTargets(ip),
			gonmap.WithPorts(ports),
			gonmap.WithServiceInfo(),
			gonmap.WithTimingTemplate(gonmap.TimingAggressive),
			gonmap.WithVersionIntensity(5),
		}, ports

	case NmapProfileDeep:
		ports := scadaPorts + ",21,25,53,110,143,389,445,1433,1521,3306,5432,6379,8161,9200,27017"
		return []func(*gonmap.Scanner){
			gonmap.WithTargets(ip),
			gonmap.WithPorts(ports),
			gonmap.WithServiceInfo(),
			gonmap.WithTimingTemplate(gonmap.TimingAggressive),
			gonmap.WithVersionIntensity(7),
			gonmap.WithScripts("banner,http-title,ssl-cert"),
			gonmap.WithVersionAll(),
		}, ports

	default: // standard
		return []func(*gonmap.Scanner){
			gonmap.WithTargets(ip),
			gonmap.WithPorts(scadaPorts),
			gonmap.WithServiceInfo(),
			gonmap.WithTimingTemplate(gonmap.TimingAggressive),
			gonmap.WithVersionIntensity(5),
			gonmap.WithScripts("banner,http-title"),
		}, scadaPorts
	}
}

// buildBanner assembles a human-readable banner from nmap service detection fields.
func buildBanner(svc gonmap.Service) string {
	if svc.Product == "" && svc.Version == "" && svc.ExtraInfo == "" {
		return svc.Name
	}
	b := svc.Product
	if svc.Version != "" {
		b += " " + svc.Version
	}
	if svc.ExtraInfo != "" {
		b += " (" + svc.ExtraInfo + ")"
	}
	if svc.DeviceType != "" {
		b += " [" + svc.DeviceType + "]"
	}
	return b
}

// portCount returns an approximate count of ports in a port specification string.
func portCount(spec string) int {
	count := 0
	for _, c := range spec {
		if c == ',' {
			count++
		}
	}
	return count + 1
}
