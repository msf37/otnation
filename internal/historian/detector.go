// Package historian detects OT historian servers by probing characteristic ports
// and HTTP endpoints for product signatures.
package historian

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

// ErrNoHistorian is returned when no historian services are detected.
var ErrNoHistorian = errors.New("historian: no historian services detected")

// Service holds information about a detected historian service.
type Service struct {
	Product  string `json:"product"`
	Port     int    `json:"port"`
	Version  string `json:"version,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// Result holds all detected historian services for an IP.
type Result struct {
	IP       string    `json:"ip"`
	Services []Service `json:"services"`
}

type candidate struct {
	product  string
	port     int
	useTLS   bool
	httpPath string // empty = TCP-only check
	sigs     []string
}

var candidates = []candidate{
	// OSIsoft PI
	{product: "OSIsoft PI API (legacy)", port: 5450},
	{product: "OSIsoft PI Server", port: 5462},
	{product: "OSIsoft PI Notification", port: 5461},
	{product: "OSIsoft PI Batch", port: 5463},
	{product: "OSIsoft PI Web API", port: 443, useTLS: true, httpPath: "/piwebapi/system", sigs: []string{"PI Web API", "OSIsoft", "piwebapi"}},
	{product: "OSIsoft PI Web API (HTTP)", port: 80, httpPath: "/piwebapi/system", sigs: []string{"PI Web API", "OSIsoft", "piwebapi"}},
	// AspenTech IP.21
	{product: "AspenTech IP.21", port: 10014},
	// Honeywell Uniformance PHD
	{product: "Honeywell Uniformance PHD", port: 3000},
	// GE Proficy Historian
	{product: "GE Proficy Historian", port: 14000},
	// eDNA Historian
	{product: "eDNA Server", port: 5000},
}

// Detect probes the given IP for historian services.
func Detect(ctx context.Context, ip string) (*Result, error) {
	result := &Result{IP: ip}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}

	for _, c := range candidates {
		select {
		case <-ctx.Done():
			break
		default:
		}

		addr := fmt.Sprintf("%s:%d", ip, c.port)
		if !tcpConnect(addr, 3*time.Second) {
			continue
		}

		svc := Service{
			Product: c.product,
			Port:    c.port,
		}

		if c.httpPath != "" {
			scheme := "http"
			if c.useTLS {
				scheme = "https"
			}
			url := fmt.Sprintf("%s://%s:%d%s", scheme, ip, c.port, c.httpPath)
			banner, version := httpProbe(ctx, httpClient, url, c.sigs)
			svc.Endpoint = c.httpPath
			svc.Banner = banner
			svc.Version = version
		} else {
			// Plain TCP — grab banner.
			svc.Banner = grabTCPBanner(addr, 2*time.Second)
		}

		result.Services = append(result.Services, svc)
	}

	if len(result.Services) == 0 {
		return nil, ErrNoHistorian
	}
	return result, nil
}

// tcpConnect checks if a TCP port is open within the given timeout.
func tcpConnect(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// grabTCPBanner connects and reads up to 256 bytes of initial banner.
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
	// Return only printable ASCII.
	out := strings.Map(func(r rune) rune {
		if r >= 0x20 && r <= 0x7E {
			return r
		}
		return -1
	}, string(buf[:n]))
	return strings.TrimSpace(out)
}

// httpProbe sends an HTTP GET and looks for signatures in the response.
// Returns (banner snippet, version string).
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

	// Check headers + body for signatures.
	serverHdr := resp.Header.Get("Server")
	xPowered := resp.Header.Get("X-Powered-By")
	combined := body + " " + serverHdr + " " + xPowered

	for _, sig := range sigs {
		if strings.Contains(strings.ToLower(combined), strings.ToLower(sig)) {
			snippet := extractSnippet(body, sig, 120)
			version := extractVersion(serverHdr + " " + xPowered)
			return snippet, version
		}
	}

	// Even if no sig matched, return the server header as banner.
	if serverHdr != "" {
		return serverHdr, ""
	}
	return "", ""
}

// extractSnippet returns up to maxLen characters around the first occurrence of sig in body.
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

// extractVersion attempts to pull a version string from a header value.
func extractVersion(header string) string {
	// Look for patterns like "2.5.0" or "v3.1".
	parts := strings.Fields(header)
	for _, p := range parts {
		p = strings.Trim(p, "()")
		if len(p) > 0 && (p[0] == 'v' || (p[0] >= '0' && p[0] <= '9')) {
			// simple heuristic: has at least one dot
			if strings.Contains(p, ".") {
				return p
			}
		}
	}
	return ""
}
