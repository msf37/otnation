// Package httpprobe provides HTTP web fingerprinting and probing capabilities.
package httpprobe

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ProbeResult holds the HTTP probe result for a single port.
type ProbeResult struct {
	Port      int               `json:"port"`
	URL       string            `json:"url"`
	StatusCode int              `json:"status_code"`
	Title     string            `json:"title"`
	Server    string            `json:"server"`
	PoweredBy string            `json:"powered_by"`
	FinalURL  string            `json:"final_url"` // after redirects
	Headers   map[string]string `json:"headers"`

	// Security headers
	HSTS          bool `json:"hsts"`
	CSP           bool `json:"csp"`
	XFrameOptions bool `json:"x_frame_options"`
	XContentType  bool `json:"x_content_type_options"`

	// Tech fingerprinting
	Technologies []string `json:"technologies"`

	// Interesting paths found
	InterestingPaths []PathResult `json:"interesting_paths,omitempty"`

	Error string `json:"error,omitempty"`
}

// PathResult holds the result of checking a specific path.
type PathResult struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
}

// Result holds the aggregate probe results for a target.
type Result struct {
	Target   string        `json:"target"` // hostname or IP
	Probes   []ProbeResult `json:"probes"`
	ProbedAt time.Time     `json:"probed_at"`
}

// defaultPorts lists the ports probed when no scan results are provided.
var defaultPorts = []int{80, 443, 8080, 8443, 8888, 9090, 3000, 5000}

// httpsFirstPorts are tried with HTTPS before HTTP.
var httpsFirstPorts = map[int]bool{443: true, 8443: true}

// interestingPaths are paths checked for exposure on each discovered web port.
var interestingPaths = []string{
	"/robots.txt",
	"/.git/HEAD",
	"/admin",
	"/wp-login.php",
	"/phpmyadmin",
	"/manager/html",
	"/actuator",
	"/.env",
}

// interestingStatusCodes reports a path as interesting if its status is one of these.
var interestingStatusCodes = map[int]bool{
	http.StatusOK:       true,
	http.StatusMovedPermanently: true,
	http.StatusFound:    true,
	http.StatusForbidden: true,
}

// Probe runs HTTP fingerprinting against target on the given open ports.
// If openPorts is empty the defaultPorts list is used.
func Probe(ctx context.Context, target string, openPorts []int) (*Result, error) {
	ports := openPorts
	if len(ports) == 0 {
		ports = defaultPorts
	} else {
		// Merge open ports with defaults so we always probe common web ports.
		portSet := make(map[int]bool)
		for _, p := range openPorts {
			portSet[p] = true
		}
		for _, p := range defaultPorts {
			portSet[p] = true
		}
		ports = make([]int, 0, len(portSet))
		for p := range portSet {
			ports = append(ports, p)
		}
		sort.Ints(ports)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	var probes []ProbeResult
	for _, port := range ports {
		select {
		case <-ctx.Done():
			break
		default:
		}
		pr := probePort(ctx, client, target, port)
		if pr.StatusCode > 0 || pr.Error == "" {
			// Only include probes that actually got a response.
			probes = append(probes, pr)
		}
	}

	return &Result{
		Target:   target,
		Probes:   probes,
		ProbedAt: time.Now().UTC(),
	}, nil
}

// probePort probes a single port and returns a ProbeResult.
func probePort(ctx context.Context, client *http.Client, target string, port int) ProbeResult {
	pr := ProbeResult{
		Port:    port,
		Headers: make(map[string]string),
	}

	// Choose scheme: HTTPS first for TLS ports.
	scheme := "http"
	if httpsFirstPorts[port] {
		scheme = "https"
	}

	rawURL := scheme + "://" + target
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		rawURL = scheme + "://" + target + ":" + itoa(port)
	}
	pr.URL = rawURL

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		pr.Error = err.Error()
		return pr
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; OTNation-Probe/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		// If HTTPS failed, try HTTP on the same port.
		if httpsFirstPorts[port] {
			fallbackURL := "http://" + target + ":" + itoa(port)
			pr.URL = fallbackURL
			req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, fallbackURL, nil)
			if err2 != nil {
				pr.Error = err.Error()
				return pr
			}
			req2.Header.Set("User-Agent", "Mozilla/5.0 (compatible; OTNation-Probe/1.0)")
			resp, err = client.Do(req2)
			if err != nil {
				pr.Error = err.Error()
				return pr
			}
		} else {
			pr.Error = err.Error()
			return pr
		}
	}
	defer resp.Body.Close()

	pr.StatusCode = resp.StatusCode
	pr.FinalURL = resp.Request.URL.String()
	if pr.FinalURL == pr.URL {
		pr.FinalURL = "" // only show if different
	}

	// Capture response headers (lowercase keys, first value only).
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			pr.Headers[strings.ToLower(k)] = vs[0]
		}
	}

	// Security headers.
	pr.HSTS = pr.Headers["strict-transport-security"] != ""
	pr.CSP = pr.Headers["content-security-policy"] != ""
	pr.XFrameOptions = pr.Headers["x-frame-options"] != ""
	pr.XContentType = pr.Headers["x-content-type-options"] != ""

	// Server / powered-by.
	pr.Server = pr.Headers["server"]
	pr.PoweredBy = pr.Headers["x-powered-by"]

	// Read up to 512 KB of body for title extraction.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	pr.Title = extractTitle(string(body))

	// Technology fingerprinting.
	pr.Technologies = detectTechnologies(pr.Headers, string(body))

	// Interesting path probing.
	pr.InterestingPaths = checkInterestingPaths(ctx, client, pr.URL, target, port)

	return pr
}

// extractTitle extracts the HTML <title> content using simple string search.
func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start == -1 {
		return ""
	}
	// Move past the opening tag.
	gt := strings.Index(body[start:], ">")
	if gt == -1 {
		return ""
	}
	contentStart := start + gt + 1
	end := strings.Index(strings.ToLower(body[contentStart:]), "</title>")
	if end == -1 {
		return ""
	}
	title := strings.TrimSpace(body[contentStart : contentStart+end])
	// Truncate very long titles.
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}

// detectTechnologies detects server-side technologies from headers and body.
func detectTechnologies(headers map[string]string, body string) []string {
	techSet := make(map[string]bool)

	server := strings.ToLower(headers["server"])
	if strings.Contains(server, "apache") {
		techSet["Apache"] = true
	}
	if strings.Contains(server, "nginx") {
		techSet["Nginx"] = true
	}
	if strings.Contains(server, "iis") || strings.Contains(server, "microsoft-iis") {
		techSet["IIS"] = true
	}
	if strings.Contains(server, "lighttpd") {
		techSet["Lighttpd"] = true
	}
	if strings.Contains(server, "caddy") {
		techSet["Caddy"] = true
	}
	if strings.Contains(server, "tomcat") {
		techSet["Tomcat"] = true
	}
	if strings.Contains(server, "jetty") {
		techSet["Jetty"] = true
	}

	poweredBy := strings.ToLower(headers["x-powered-by"])
	if strings.Contains(poweredBy, "php") {
		techSet["PHP"] = true
	}
	if strings.Contains(poweredBy, "asp.net") {
		techSet["ASP.NET"] = true
	}
	if strings.Contains(poweredBy, "express") {
		techSet["Express"] = true
	}
	if strings.Contains(poweredBy, "next.js") {
		techSet["Next.js"] = true
	}

	if gen := headers["x-generator"]; gen != "" {
		techSet[gen] = true
	}

	// Cookie-based CMS detection.
	setCookie := strings.ToLower(headers["set-cookie"])
	if strings.Contains(setCookie, "wordpress_") || strings.Contains(setCookie, "wp-settings") {
		techSet["WordPress"] = true
	}
	if strings.Contains(setCookie, "sess") && strings.Contains(body, "drupal") {
		techSet["Drupal"] = true
	}
	if strings.Contains(setCookie, "joomla") {
		techSet["Joomla"] = true
	}

	// Via header — proxy/CDN.
	if via := headers["via"]; via != "" {
		techSet["Proxy/CDN ("+via+")"] = true
	}

	// Body-based detection.
	lowerBody := strings.ToLower(body)
	if strings.Contains(lowerBody, "wp-content/") || strings.Contains(lowerBody, "wp-includes/") {
		techSet["WordPress"] = true
	}
	if strings.Contains(lowerBody, "drupal.js") || strings.Contains(lowerBody, "/sites/default/") {
		techSet["Drupal"] = true
	}
	if strings.Contains(lowerBody, "joomla") {
		techSet["Joomla"] = true
	}

	techs := make([]string, 0, len(techSet))
	for t := range techSet {
		techs = append(techs, t)
	}
	sort.Strings(techs)
	return techs
}

// checkInterestingPaths probes known sensitive paths and returns those that respond
// with interesting status codes.
func checkInterestingPaths(ctx context.Context, client *http.Client, baseURL, target string, port int) []PathResult {
	pathClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	_ = pathClient // use below

	var results []PathResult
	for _, path := range interestingPaths {
		fullURL := baseURL + path

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; OTNation-Probe/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if interestingStatusCodes[resp.StatusCode] {
			results = append(results, PathResult{
				Path:       path,
				StatusCode: resp.StatusCode,
			})
		}
	}
	return results
}

// itoa converts an int to a string without importing strconv directly.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
