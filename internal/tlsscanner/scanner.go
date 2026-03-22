// Package tlsscanner performs TLS certificate and protocol analysis for domains.
package tlsscanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// Issue describes a single TLS security finding.
type Issue struct {
	Severity    string `json:"severity"`    // critical | high | medium | info
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Result is the full output of a TLS scan.
type Result struct {
	CommonName      string     `json:"common_name"`
	Issuer          string     `json:"issuer"`
	SANs            []string   `json:"sans"`
	NotBefore       *time.Time `json:"not_before"`
	NotAfter        *time.Time `json:"not_after"`
	DaysUntilExpiry *int       `json:"days_until_expiry"`
	TLSVersion      string     `json:"tls_version"`
	CipherSuite     string     `json:"cipher_suite"`
	KeyAlgorithm    string     `json:"key_algorithm"`
	KeySize         int        `json:"key_size"`
	SignatureAlgo   string     `json:"signature_algo"`
	Grade           string     `json:"grade"`
	Issues          []Issue    `json:"issues"`
	ErrorMsg        string     `json:"error_msg,omitempty"`
}

// Scan connects to domain:443, inspects the TLS handshake and certificate,
// and returns a Result. It never returns a Go error — connection failures are
// captured in Result.ErrorMsg with Grade "F".
func Scan(ctx context.Context, domain string) *Result {
	r := &Result{SANs: []string{}, Issues: []Issue{}}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // we inspect manually below
		ServerName:         domain,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", tlsCfg)
	if err != nil {
		r.ErrorMsg = err.Error()
		r.Grade = "F"
		r.Issues = append(r.Issues, Issue{
			Severity:    "critical",
			Title:       "Connection Failed",
			Description: fmt.Sprintf("Could not establish TLS connection to %s:443 — %s", domain, err.Error()),
		})
		return r
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// --- Protocol version ---
	r.TLSVersion = versionName(state.Version)
	r.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	switch state.Version {
	case tls.VersionTLS10:
		r.Issues = append(r.Issues, Issue{
			Severity:    "high",
			Title:       "TLS 1.0 Negotiated",
			Description: "TLS 1.0 is deprecated (RFC 8996). Disable it and enforce TLS 1.2+.",
		})
	case tls.VersionTLS11:
		r.Issues = append(r.Issues, Issue{
			Severity:    "medium",
			Title:       "TLS 1.1 Negotiated",
			Description: "TLS 1.1 is deprecated (RFC 8996). Upgrade to TLS 1.2 or 1.3.",
		})
	}

	// --- Weak cipher suite ---
	csUpper := strings.ToUpper(r.CipherSuite)
	for _, weak := range []string{"RC4", "_DES_", "3DES", "NULL", "EXPORT", "ANON"} {
		if strings.Contains(csUpper, weak) {
			r.Issues = append(r.Issues, Issue{
				Severity:    "critical",
				Title:       "Weak Cipher Suite",
				Description: fmt.Sprintf("Negotiated cipher %q is considered insecure.", r.CipherSuite),
			})
			break
		}
	}

	// --- Certificate ---
	if len(state.PeerCertificates) == 0 {
		r.Grade = calculateGrade(r.Issues)
		return r
	}

	cert := state.PeerCertificates[0]

	r.CommonName = cert.Subject.CommonName
	r.Issuer = cert.Issuer.CommonName
	r.SANs = cert.DNSNames
	nb := cert.NotBefore
	na := cert.NotAfter
	r.NotBefore = &nb
	r.NotAfter = &na
	days := int(time.Until(na).Hours() / 24)
	r.DaysUntilExpiry = &days

	// Signature algorithm
	r.SignatureAlgo = cert.SignatureAlgorithm.String()
	sigUpper := strings.ToUpper(r.SignatureAlgo)
	if strings.Contains(sigUpper, "SHA1") || strings.Contains(sigUpper, "MD5") {
		r.Issues = append(r.Issues, Issue{
			Severity:    "medium",
			Title:       "Weak Signature Algorithm",
			Description: fmt.Sprintf("Certificate signed with %s which is considered weak.", r.SignatureAlgo),
		})
	}

	// Key algorithm and size
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		r.KeyAlgorithm = "RSA"
		r.KeySize = pub.N.BitLen()
		if r.KeySize < 2048 {
			r.Issues = append(r.Issues, Issue{
				Severity:    "high",
				Title:       "Weak RSA Key",
				Description: fmt.Sprintf("RSA key is %d bits — minimum recommended is 2048.", r.KeySize),
			})
		}
	case *ecdsa.PublicKey:
		r.KeyAlgorithm = "ECDSA"
		r.KeySize = pub.Curve.Params().BitSize
		if r.KeySize < 256 {
			r.Issues = append(r.Issues, Issue{
				Severity:    "medium",
				Title:       "Weak ECDSA Key",
				Description: fmt.Sprintf("ECDSA key is %d bits — minimum recommended is 256.", r.KeySize),
			})
		}
	default:
		r.KeyAlgorithm = "Unknown"
	}

	// Expiry
	now := time.Now()
	switch {
	case now.After(na):
		r.Issues = append(r.Issues, Issue{
			Severity:    "critical",
			Title:       "Certificate Expired",
			Description: fmt.Sprintf("Expired %d day(s) ago on %s.", -days, na.Format("2006-01-02")),
		})
	case days < 14:
		r.Issues = append(r.Issues, Issue{
			Severity:    "critical",
			Title:       "Certificate Expiring Imminently",
			Description: fmt.Sprintf("Expires in %d day(s) on %s.", days, na.Format("2006-01-02")),
		})
	case days < 30:
		r.Issues = append(r.Issues, Issue{
			Severity:    "high",
			Title:       "Certificate Expiring Soon",
			Description: fmt.Sprintf("Expires in %d days on %s.", days, na.Format("2006-01-02")),
		})
	case days < 90:
		r.Issues = append(r.Issues, Issue{
			Severity:    "medium",
			Title:       "Certificate Expires Within 90 Days",
			Description: fmt.Sprintf("Expires in %d days on %s.", days, na.Format("2006-01-02")),
		})
	}

	// Self-signed
	if cert.Issuer.String() == cert.Subject.String() {
		r.Issues = append(r.Issues, Issue{
			Severity:    "high",
			Title:       "Self-Signed Certificate",
			Description: "Certificate is not issued by a recognised CA.",
		})
	}

	// Domain mismatch
	if err := cert.VerifyHostname(domain); err != nil {
		r.Issues = append(r.Issues, Issue{
			Severity:    "high",
			Title:       "Certificate Domain Mismatch",
			Description: fmt.Sprintf("Certificate does not cover %s: %s", domain, err.Error()),
		})
	}

	r.Grade = calculateGrade(r.Issues)
	return r
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func calculateGrade(issues []Issue) string {
	grade := "A"
	for _, i := range issues {
		switch i.Severity {
		case "critical":
			return "F"
		case "high":
			if grade == "A" || grade == "B" {
				grade = "C"
			}
		case "medium":
			if grade == "A" {
				grade = "B"
			}
		}
	}
	return grade
}
