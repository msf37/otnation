// Package hmi detects SCADA HMI software by probing characteristic ports
// and HTTP endpoints for product signatures.
package hmi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ErrNoHMI is returned when no HMI software is detected.
var ErrNoHMI = errors.New("hmi: no HMI software detected")

// HMIResult holds information about a detected HMI instance.
type HMIResult struct {
	Product  string `json:"product"`
	Vendor   string `json:"vendor"`
	Port     int    `json:"port"`
	Version  string `json:"version,omitempty"`
	Evidence string `json:"evidence"`
	RiskNote string `json:"risk_note"`
}

// Result holds all detected HMIs for an IP.
type Result struct {
	IP   string      `json:"ip"`
	HMIs []HMIResult `json:"hmis"`
}

type hmiCandidate struct {
	product  string
	vendor   string
	port     int
	useTLS   bool
	httpPath string
	sigs     []string
	riskNote string
}

var hmiCandidates = []hmiCandidate{
	// Siemens WinCC
	{product: "WinCC ISO-TSAP", vendor: "Siemens", port: 102, riskNote: "Siemens S7/ISO-TSAP port open — likely WinCC or Step 7 environment"},
	{product: "WinCC OPC-UA", vendor: "Siemens", port: 4840, httpPath: "/", sigs: []string{"opc.tcp", "opcua", "OPC"}, riskNote: "OPC-UA exposed — attacker can enumerate process data"},
	{product: "WinCC Web Navigator", vendor: "Siemens", port: 8088, httpPath: "/", sigs: []string{"WinCC", "Siemens", "SCADA"}, riskNote: "WinCC Web Navigator exposed — remote HMI access possible"},
	// Schneider Electric
	{product: "Schneider Modbus", vendor: "Schneider Electric", port: 502, riskNote: "Modbus TCP exposed — no authentication, read/write access to PLC data"},
	{product: "Schneider Unity (UMAS)", vendor: "Schneider Electric", port: 2222, riskNote: "UMAS protocol port open — Schneider Unity Pro may be reachable"},
	{product: "Schneider Web HMI", vendor: "Schneider Electric", port: 80, httpPath: "/", sigs: []string{"Schneider", "EcoStruxure", "Unity", "Modicon"}, riskNote: "Schneider web interface exposed"},
	{product: "Schneider Web HMI TLS", vendor: "Schneider Electric", port: 443, useTLS: true, httpPath: "/", sigs: []string{"Schneider", "EcoStruxure", "Unity", "Modicon"}, riskNote: "Schneider web interface exposed over HTTPS"},
	// GE iFIX / Cimplicity
	{product: "GE iFIX Web Space", vendor: "GE", port: 82, httpPath: "/", sigs: []string{"iFIX", "GE", "Proficy"}, riskNote: "GE iFIX web interface exposed"},
	{product: "GE Cimplicity Web", vendor: "GE", port: 10212, httpPath: "/", sigs: []string{"Cimplicity", "GE", "Proficy"}, riskNote: "GE Cimplicity web server exposed"},
	// Wonderware / AVEVA
	{product: "Wonderware Online", vendor: "AVEVA", port: 8443, useTLS: true, httpPath: "/", sigs: []string{"Wonderware", "AVEVA", "InTouch"}, riskNote: "Wonderware/AVEVA InTouch web interface exposed"},
	{product: "Wonderware HTTP", vendor: "AVEVA", port: 80, httpPath: "/", sigs: []string{"Wonderware", "AVEVA", "InTouch", "System Platform"}, riskNote: "Wonderware/AVEVA web interface exposed"},
	// Citect SCADA
	{product: "Citect SCADA Server", vendor: "AVEVA", port: 20222, riskNote: "Citect SCADA server port open — proprietary protocol access possible"},
	{product: "Citect Web", vendor: "AVEVA", port: 80, httpPath: "/", sigs: []string{"Citect", "vijeo"}, riskNote: "Citect SCADA web interface exposed"},
	// Honeywell Experion
	{product: "Honeywell Experion Server", vendor: "Honeywell", port: 55555, riskNote: "Honeywell Experion server port open"},
	{product: "Honeywell Experion Web", vendor: "Honeywell", port: 443, useTLS: true, httpPath: "/", sigs: []string{"Experion", "Honeywell", "PKS"}, riskNote: "Honeywell Experion web interface exposed"},
	// OSIsoft PI (cross-check)
	{product: "OSIsoft PI API", vendor: "OSIsoft", port: 5450, riskNote: "OSIsoft PI API port open — process historian accessible"},
	{product: "OSIsoft PI Server", vendor: "OSIsoft", port: 5462, riskNote: "OSIsoft PI Server port open — process historian accessible"},
}

// Fingerprint probes the given IP for SCADA HMI software.
func Fingerprint(ctx context.Context, ip string) (*Result, error) {
	result := &Result{IP: ip}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}

	// Track (port, product) combos already found to avoid duplicate entries.
	seen := map[string]bool{}

	for _, c := range hmiCandidates {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		key := fmt.Sprintf("%s:%d", c.product, c.port)
		if seen[key] {
			continue
		}

		addr := fmt.Sprintf("%s:%d", ip, c.port)
		if !tcpConnect(addr, 3*time.Second) {
			continue
		}

		hmi := HMIResult{
			Product:  c.product,
			Vendor:   c.vendor,
			Port:     c.port,
			RiskNote: c.riskNote,
		}

		if c.httpPath != "" {
			scheme := "http"
			if c.useTLS {
				scheme = "https"
			}
			url := fmt.Sprintf("%s://%s:%d%s", scheme, ip, c.port, c.httpPath)
			evidence, version := httpProbe(ctx, httpClient, url, c.sigs)
			hmi.Evidence = evidence
			hmi.Version = version
			if hmi.Evidence == "" {
				hmi.Evidence = fmt.Sprintf("Port %d open (TCP connect)", c.port)
			}
		} else {
			banner := grabTCPBanner(addr, 2*time.Second)
			if banner != "" {
				hmi.Evidence = fmt.Sprintf("Port %d open; banner: %s", c.port, banner)
			} else {
				hmi.Evidence = fmt.Sprintf("Port %d open (TCP connect)", c.port)
			}
		}

		seen[key] = true
		result.HMIs = append(result.HMIs, hmi)
	}

done:
	if len(result.HMIs) == 0 {
		return nil, ErrNoHMI
	}
	return result, nil
}

func tcpConnect(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func grabTCPBanner(addr string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	out := strings.Map(func(r rune) rune {
		if r >= 0x20 && r <= 0x7E {
			return r
		}
		return -1
	}, string(buf[:n]))
	return strings.TrimSpace(out)
}

func httpProbe(ctx context.Context, client *http.Client, url string, sigs []string) (string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 OTNation-Platform")

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	body := string(bodyBytes)
	serverHdr := resp.Header.Get("Server")
	combined := body + " " + serverHdr

	for _, sig := range sigs {
		if strings.Contains(strings.ToLower(combined), strings.ToLower(sig)) {
			snippet := extractSnippet(body, sig, 120)
			version := extractVersion(serverHdr)
			return snippet, version
		}
	}

	if serverHdr != "" {
		return serverHdr, ""
	}
	return "", ""
}

func extractSnippet(body, sig string, maxLen int) string {
	lower := strings.ToLower(body)
	idx := strings.Index(lower, strings.ToLower(sig))
	if idx < 0 {
		if len(body) > maxLen {
			return body[:maxLen] + "..."
		}
		return body
	}
	start := idx - 20
	if start < 0 {
		start = 0
	}
	end := idx + len(sig) + 60
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(body[start:end])
}

func extractVersion(header string) string {
	parts := strings.Fields(header)
	for _, p := range parts {
		p = strings.Trim(p, "()")
		if len(p) > 0 && (p[0] == 'v' || (p[0] >= '0' && p[0] <= '9')) {
			if strings.Contains(p, ".") {
				return p
			}
		}
	}
	return ""
}
