package threatintel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var ErrNoResponse = errors.New("defcreds: target not reachable")

type CredResult struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Method   string `json:"method"`
	Success  bool   `json:"success"`
	Status   int    `json:"http_status,omitempty"`
}

type DefaultCredReport struct {
	IP      string       `json:"ip"`
	Found   bool         `json:"found"`
	Results []CredResult `json:"results"`
}

type credPair struct {
	vendor   string
	username string
	password string
	paths    []string
}

var defaultCreds = []credPair{
	{vendor: "Generic", username: "admin", password: "admin", paths: []string{"/", "/login", "/index.html"}},
	{vendor: "Generic", username: "admin", password: "password", paths: []string{"/", "/login"}},
	{vendor: "Generic", username: "admin", password: "", paths: []string{"/", "/login"}},
	{vendor: "Generic", username: "admin", password: "1234", paths: []string{"/"}},
	{vendor: "Generic", username: "root", password: "root", paths: []string{"/"}},
	{vendor: "Generic", username: "root", password: "", paths: []string{"/"}},
	{vendor: "Generic", username: "user", password: "user", paths: []string{"/"}},
	{vendor: "Siemens WinCC", username: "admin", password: "admin", paths: []string{"/Portal/Portal.mwsl", "/"}},
	{vendor: "Siemens WinCC", username: "Administrator", password: "", paths: []string{"/Portal/Portal.mwsl"}},
	{vendor: "Schneider Electric", username: "USER", password: "USER", paths: []string{"/", "/index.html"}},
	{vendor: "Schneider Electric", username: "ADMIN", password: "ADMIN", paths: []string{"/", "/index.html"}},
	{vendor: "GE iFIX", username: "administrator", password: "", paths: []string{"/", "/login"}},
	{vendor: "Honeywell Experion", username: "admin", password: "admin", paths: []string{"/", "/apps/controllerframe/"}},
	{vendor: "Honeywell Experion", username: "Admin", password: "Admin", paths: []string{"/"}},
	{vendor: "ABB", username: "admin", password: "admin", paths: []string{"/"}},
	{vendor: "ABB", username: "user", password: "user", paths: []string{"/"}},
}

func TestDefaultCreds(ctx context.Context, ip string) (*DefaultCredReport, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	report := &DefaultCredReport{IP: ip}
	reachable := false

	for _, cred := range defaultCreds {
		for _, scheme := range []string{"http", "https"} {
			for _, path := range cred.paths {
				select {
				case <-ctx.Done():
					return report, nil
				default:
				}

				url := fmt.Sprintf("%s://%s%s", scheme, ip, path)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth(cred.username, cred.password)
				req.Header.Set("User-Agent", "Mozilla/5.0 OTNation-Security")

				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				reachable = true
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
				resp.Body.Close()
				bodyStr := strings.ToLower(string(body))

				cr := CredResult{
					URL:      url,
					Username: cred.username,
					Password: cred.password,
					Method:   "basic_auth",
					Status:   resp.StatusCode,
				}

				// Success if 200 OK and not a login page, or if 302 to non-login URL
				isLoginPage := strings.Contains(bodyStr, "login") && strings.Contains(bodyStr, "password") && resp.StatusCode == 200
				if (resp.StatusCode == http.StatusOK && !isLoginPage) ||
					(resp.StatusCode == http.StatusFound && !strings.Contains(resp.Header.Get("Location"), "login")) {
					cr.Success = true
					report.Found = true
				}

				report.Results = append(report.Results, cr)
				if cr.Success {
					break // found for this cred pair
				}
			}
		}
	}

	if !reachable {
		return nil, ErrNoResponse
	}
	return report, nil
}
