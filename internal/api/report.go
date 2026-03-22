package api

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
	"github.com/otnation/platform/internal/models"
	"github.com/otnation/platform/internal/store"
)

const pdfReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OT Security Report — {{.Identity.Name}}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; color: #1a1a2e; background: #fff; }
  h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
  h2 { font-size: 18px; font-weight: 600; margin-bottom: 12px; color: #16213e; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }
  h3 { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
  p  { margin-bottom: 8px; line-height: 1.5; }
  .cover { padding: 80px 60px; border-bottom: 4px solid #e63946; page-break-after: always; }
  .cover .org { font-size: 15px; color: #555; margin-bottom: 4px; }
  .cover .date { font-size: 13px; color: #888; margin-top: 16px; }
  .cover .badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 700; background: #e63946; color: #fff; margin-top: 12px; }
  .section { padding: 40px 60px; page-break-inside: avoid; }
  .section + .section { border-top: 1px solid #e2e8f0; }
  .stat-grid { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 24px; }
  .stat-card { flex: 1; min-width: 120px; padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px; text-align: center; }
  .stat-card .val { font-size: 28px; font-weight: 700; color: #16213e; }
  .stat-card .lbl { font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 12px; }
  th { background: #f8fafc; padding: 8px 10px; text-align: left; font-weight: 600; border-bottom: 2px solid #e2e8f0; }
  td { padding: 7px 10px; border-bottom: 1px solid #f0f4f8; vertical-align: top; }
  tr:hover td { background: #f8fafc; }
  .sev { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
  .sev-critical { background: #fee2e2; color: #b91c1c; }
  .sev-high     { background: #ffedd5; color: #c2410c; }
  .sev-medium   { background: #fef3c7; color: #b45309; }
  .sev-low      { background: #dcfce7; color: #15803d; }
  .sev-informational { background: #f0f9ff; color: #0369a1; }
  .footer { padding: 24px 60px; color: #aaa; font-size: 11px; border-top: 1px solid #e2e8f0; }
  @page { size: A4; margin: 20mm; }
  @media print {
    .no-print { display: none !important; }
    .cover { page-break-after: always; }
    body { font-size: 11px; }
    .section { padding: 20px 30px; page-break-inside: avoid; }
    .cover { padding: 40px 30px; }
  }
</style>
</head>
<body>

<!-- COVER PAGE -->
<div class="cover">
  <div class="org">{{.Identity.OrgName}}</div>
  <h1>OT Security Assessment Report</h1>
  <div style="font-size:20px;color:#555;margin-bottom:8px">{{.Identity.Name}}</div>
  {{if .Identity.Sector}}<div style="font-size:13px;color:#777;margin-bottom:4px">Sector: {{.Identity.Sector}}</div>{{end}}
  <div class="badge">CONFIDENTIAL</div>
  <div class="date">Generated: {{.GeneratedAt}}</div>
  {{if .Identity.Notes}}<p style="margin-top:24px;color:#555">{{.Identity.Notes}}</p>{{end}}
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="section">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat-card"><div class="val">{{.Stats.TotalAssets}}</div><div class="lbl">Total Assets</div></div>
    <div class="stat-card"><div class="val">{{.Stats.TotalIPs}}</div><div class="lbl">IP Addresses</div></div>
    <div class="stat-card"><div class="val">{{.Stats.TotalDomains}}</div><div class="lbl">Domains</div></div>
    <div class="stat-card"><div class="val">{{.Stats.OpenPorts}}</div><div class="lbl">Open Ports</div></div>
    <div class="stat-card" style="border-color:#b91c1c"><div class="val" style="color:#b91c1c">{{index .Stats.FindingsBySeverity "critical"}}</div><div class="lbl">Critical</div></div>
    <div class="stat-card" style="border-color:#c2410c"><div class="val" style="color:#c2410c">{{index .Stats.FindingsBySeverity "high"}}</div><div class="lbl">High</div></div>
    <div class="stat-card" style="border-color:#b45309"><div class="val" style="color:#b45309">{{index .Stats.FindingsBySeverity "medium"}}</div><div class="lbl">Medium</div></div>
    <div class="stat-card" style="border-color:#15803d"><div class="val" style="color:#15803d">{{index .Stats.FindingsBySeverity "low"}}</div><div class="lbl">Low</div></div>
  </div>
</div>

<!-- ASSET TABLE -->
<div class="section">
  <h2>Asset Inventory ({{len .Assets}})</h2>
  {{if .Assets}}
  <table>
    <thead><tr><th>Asset Value</th><th>Type</th><th>Country</th><th>ASN Org</th><th>Provenance</th></tr></thead>
    <tbody>
    {{range .Assets}}
    <tr>
      <td>{{.Value}}</td>
      <td>{{.Type}}</td>
      <td>{{if .CountryCode}}{{.CountryCode}}{{else}}&mdash;{{end}}</td>
      <td>{{if .ASNOrg}}{{.ASNOrg}}{{else}}&mdash;{{end}}</td>
      <td>{{.Provenance}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}<p style="color:#888">No assets found.</p>{{end}}
</div>

<!-- FINDINGS TABLE -->
<div class="section">
  <h2>Security Findings ({{len .Findings}})</h2>
  {{if .Findings}}
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Vendor</th><th>Protocol</th></tr></thead>
    <tbody>
    {{range .Findings}}
    <tr>
      <td><span class="sev sev-{{.Severity}}">{{.Severity}}</span></td>
      <td>{{.Title}}</td>
      <td>{{if .Category}}{{.Category}}{{else}}&mdash;{{end}}</td>
      <td>{{if .Vendor}}{{.Vendor}}{{else}}&mdash;{{end}}</td>
      <td>{{if .Protocol}}{{.Protocol}}{{else}}&mdash;{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}<p style="color:#888">No findings recorded.</p>{{end}}
</div>

<!-- FINDING DETAILS -->
{{if .Findings}}
<div class="section">
  <h2>Finding Details</h2>
  {{range .Findings}}
  <div style="margin-bottom:20px;padding:14px;border:1px solid #e2e8f0;border-radius:6px;border-left:4px solid {{sevColor .Severity}}">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
      <span class="sev sev-{{.Severity}}">{{.Severity}}</span>
      <strong>{{.Title}}</strong>
    </div>
    {{if .Description}}<p style="color:#444;font-size:12px">{{.Description}}</p>{{end}}
    <div style="font-size:11px;color:#888;margin-top:4px">Created: {{.CreatedAt.Format "2006-01-02"}}</div>
  </div>
  {{end}}
</div>
{{end}}

<!-- APPENDIX -->
<div class="section">
  <h2>Appendix — Scan Summary</h2>
  <p>This report was generated automatically by the OTNation Platform on {{.GeneratedAt}}. All findings should be validated by qualified security professionals before remediation actions are taken.</p>
  <p style="margin-top:8px;color:#888">Identity ID: {{.Identity.ID}}</p>
</div>

<div class="footer">
  OTNation Platform &mdash; Confidential OT Security Assessment &mdash; {{.GeneratedAt}}
</div>

</body>
</html>`

const reportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OT Security Report — {{.Identity.Name}}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; color: #1a1a2e; background: #fff; }
  h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
  h2 { font-size: 18px; font-weight: 600; margin-bottom: 12px; color: #16213e; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }
  h3 { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
  p  { margin-bottom: 8px; line-height: 1.5; }
  .cover { padding: 80px 60px; border-bottom: 4px solid #e63946; page-break-after: always; }
  .cover .org { font-size: 15px; color: #555; margin-bottom: 4px; }
  .cover .date { font-size: 13px; color: #888; margin-top: 16px; }
  .cover .badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 700; background: #e63946; color: #fff; margin-top: 12px; }
  .section { padding: 40px 60px; page-break-inside: avoid; }
  .section + .section { border-top: 1px solid #e2e8f0; }
  .stat-grid { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 24px; }
  .stat-card { flex: 1; min-width: 120px; padding: 16px; border: 1px solid #e2e8f0; border-radius: 8px; text-align: center; }
  .stat-card .val { font-size: 28px; font-weight: 700; color: #16213e; }
  .stat-card .lbl { font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 12px; }
  th { background: #f8fafc; padding: 8px 10px; text-align: left; font-weight: 600; border-bottom: 2px solid #e2e8f0; }
  td { padding: 7px 10px; border-bottom: 1px solid #f0f4f8; vertical-align: top; }
  tr:hover td { background: #f8fafc; }
  .sev { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
  .sev-critical { background: #fee2e2; color: #b91c1c; }
  .sev-high     { background: #ffedd5; color: #c2410c; }
  .sev-medium   { background: #fef3c7; color: #b45309; }
  .sev-low      { background: #dcfce7; color: #15803d; }
  .sev-informational { background: #f0f9ff; color: #0369a1; }
  .print-btn { position: fixed; top: 16px; right: 16px; padding: 8px 20px; background: #16213e; color: #fff; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; z-index: 9999; }
  .footer { padding: 24px 60px; color: #aaa; font-size: 11px; border-top: 1px solid #e2e8f0; }
  @media print {
    .no-print { display: none !important; }
    .cover { page-break-after: always; }
    body { font-size: 11px; }
    .section { padding: 20px 30px; }
    .cover { padding: 40px 30px; }
  }
</style>
</head>
<body>

<button class="print-btn no-print" onclick="window.print()">&#128438; Print / Save as PDF</button>

<!-- COVER PAGE -->
<div class="cover">
  <div class="org">{{.Identity.OrgName}}</div>
  <h1>OT Security Assessment Report</h1>
  <div style="font-size:20px;color:#555;margin-bottom:8px">{{.Identity.Name}}</div>
  {{if .Identity.Sector}}<div style="font-size:13px;color:#777;margin-bottom:4px">Sector: {{.Identity.Sector}}</div>{{end}}
  <div class="badge">CONFIDENTIAL</div>
  <div class="date">Generated: {{.GeneratedAt}}</div>
  {{if .Identity.Notes}}<p style="margin-top:24px;color:#555">{{.Identity.Notes}}</p>{{end}}
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="section">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat-card"><div class="val">{{.Stats.TotalAssets}}</div><div class="lbl">Total Assets</div></div>
    <div class="stat-card"><div class="val">{{.Stats.TotalIPs}}</div><div class="lbl">IP Addresses</div></div>
    <div class="stat-card"><div class="val">{{.Stats.TotalDomains}}</div><div class="lbl">Domains</div></div>
    <div class="stat-card"><div class="val">{{.Stats.OpenPorts}}</div><div class="lbl">Open Ports</div></div>
    <div class="stat-card" style="border-color:#b91c1c"><div class="val" style="color:#b91c1c">{{index .Stats.FindingsBySeverity "critical"}}</div><div class="lbl">Critical</div></div>
    <div class="stat-card" style="border-color:#c2410c"><div class="val" style="color:#c2410c">{{index .Stats.FindingsBySeverity "high"}}</div><div class="lbl">High</div></div>
    <div class="stat-card" style="border-color:#b45309"><div class="val" style="color:#b45309">{{index .Stats.FindingsBySeverity "medium"}}</div><div class="lbl">Medium</div></div>
    <div class="stat-card" style="border-color:#15803d"><div class="val" style="color:#15803d">{{index .Stats.FindingsBySeverity "low"}}</div><div class="lbl">Low</div></div>
  </div>
</div>

<!-- ASSET TABLE -->
<div class="section">
  <h2>Asset Inventory ({{len .Assets}})</h2>
  {{if .Assets}}
  <table>
    <thead><tr><th>Asset Value</th><th>Type</th><th>Country</th><th>ASN Org</th><th>Provenance</th></tr></thead>
    <tbody>
    {{range .Assets}}
    <tr>
      <td>{{.Value}}</td>
      <td>{{.Type}}</td>
      <td>{{if .CountryCode}}{{.CountryCode}}{{else}}&mdash;{{end}}</td>
      <td>{{if .ASNOrg}}{{.ASNOrg}}{{else}}&mdash;{{end}}</td>
      <td>{{.Provenance}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}<p style="color:#888">No assets found.</p>{{end}}
</div>

<!-- FINDINGS TABLE -->
<div class="section">
  <h2>Security Findings ({{len .Findings}})</h2>
  {{if .Findings}}
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Vendor</th><th>Protocol</th></tr></thead>
    <tbody>
    {{range .Findings}}
    <tr>
      <td><span class="sev sev-{{.Severity}}">{{.Severity}}</span></td>
      <td>{{.Title}}</td>
      <td>{{if .Category}}{{.Category}}{{else}}&mdash;{{end}}</td>
      <td>{{if .Vendor}}{{.Vendor}}{{else}}&mdash;{{end}}</td>
      <td>{{if .Protocol}}{{.Protocol}}{{else}}&mdash;{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}<p style="color:#888">No findings recorded.</p>{{end}}
</div>

<!-- FINDING DETAILS -->
{{if .Findings}}
<div class="section">
  <h2>Finding Details</h2>
  {{range .Findings}}
  <div style="margin-bottom:20px;padding:14px;border:1px solid #e2e8f0;border-radius:6px;border-left:4px solid {{sevColor .Severity}}">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
      <span class="sev sev-{{.Severity}}">{{.Severity}}</span>
      <strong>{{.Title}}</strong>
    </div>
    {{if .Description}}<p style="color:#444;font-size:12px">{{.Description}}</p>{{end}}
    <div style="font-size:11px;color:#888;margin-top:4px">Created: {{.CreatedAt.Format "2006-01-02"}}</div>
  </div>
  {{end}}
</div>
{{end}}

<!-- APPENDIX -->
<div class="section">
  <h2>Appendix — Scan Summary</h2>
  <p>This report was generated automatically by the OTNation Platform on {{.GeneratedAt}}. All findings should be validated by qualified security professionals before remediation actions are taken.</p>
  <p style="margin-top:8px;color:#888">Identity ID: {{.Identity.ID}}</p>
</div>

<div class="footer">
  OTNation Platform &mdash; Confidential OT Security Assessment &mdash; {{.GeneratedAt}}
</div>

</body>
</html>`

// reportData is passed to the HTML template.
type reportData struct {
	Identity    models.Identity
	Stats       store.IdentityStats
	Assets      []models.Asset
	Findings    []models.Finding
	GeneratedAt string
}

// HandleGenerateReport handles GET /api/v1/identities/{id}/report.
// Generates and serves a print-ready HTML report for the identity.
func HandleGenerateReport(st *store.Store) http.HandlerFunc {
	funcMap := template.FuncMap{
		"sevColor": func(sev models.SeverityLevel) string {
			switch sev {
			case models.SeverityCritical:
				return "#b91c1c"
			case models.SeverityHigh:
				return "#c2410c"
			case models.SeverityMedium:
				return "#b45309"
			case models.SeverityLow:
				return "#15803d"
			default:
				return "#0369a1"
			}
		},
	}

	tmpl := template.Must(template.New("report").Funcs(funcMap).Parse(reportTemplate))

	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}

		identity, err := st.GetIdentity(r.Context(), id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "identity not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get identity")
			return
		}

		stats, err := st.GetIdentityStats(r.Context(), id)
		if err != nil {
			stats = store.IdentityStats{FindingsBySeverity: map[string]int64{}}
		}

		// Fetch all assets (up to 1000).
		assets, err := st.ListAssets(r.Context(), store.AssetFilters{
			IdentityID: &id,
			Limit:      1000,
			Page:       1,
		})
		if err != nil {
			assets = nil
		}

		// Fetch all findings sorted by severity (up to 500).
		findings, err := st.ListFindings(r.Context(), store.FindingFilters{
			IdentityID: &id,
			Limit:      500,
			Page:       1,
		})
		if err != nil {
			findings = nil
		}

		data := reportData{
			Identity:    identity,
			Stats:       stats,
			Assets:      assets,
			Findings:    findings,
			GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		}

		// Build page title for Content-Disposition.
		safeTitle := strings.ReplaceAll(identity.Name, " ", "_")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s_report.html"`, safeTitle))

		if err := tmpl.Execute(w, data); err != nil {
			// Can't write error to response body since headers/content already sent.
			return
		}
	}
}

// HandleGenerateReportPDF handles GET /api/v1/identities/{id}/report.pdf.
// Generates and serves a print-ready HTML report optimised for PDF saving.
// Sets Content-Disposition: attachment so browsers prompt for download.
func HandleGenerateReportPDF(st *store.Store) http.HandlerFunc {
	funcMap := template.FuncMap{
		"sevColor": func(sev models.SeverityLevel) string {
			switch sev {
			case models.SeverityCritical:
				return "#b91c1c"
			case models.SeverityHigh:
				return "#c2410c"
			case models.SeverityMedium:
				return "#b45309"
			case models.SeverityLow:
				return "#15803d"
			default:
				return "#0369a1"
			}
		},
	}

	tmpl := template.Must(template.New("report_pdf").Funcs(funcMap).Parse(pdfReportTemplate))

	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseUUID(mux.Vars(r)["id"])
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid identity id")
			return
		}

		identity, err := st.GetIdentity(r.Context(), id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				writeError(w, http.StatusNotFound, "identity not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to get identity")
			return
		}

		stats, err := st.GetIdentityStats(r.Context(), id)
		if err != nil {
			stats = store.IdentityStats{FindingsBySeverity: map[string]int64{}}
		}

		assets, err := st.ListAssets(r.Context(), store.AssetFilters{
			IdentityID: &id,
			Limit:      1000,
			Page:       1,
		})
		if err != nil {
			assets = nil
		}

		findings, err := st.ListFindings(r.Context(), store.FindingFilters{
			IdentityID: &id,
			Limit:      500,
			Page:       1,
		})
		if err != nil {
			findings = nil
		}

		data := reportData{
			Identity:    identity,
			Stats:       stats,
			Assets:      assets,
			Findings:    findings,
			GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		}

		safeTitle := strings.ReplaceAll(identity.Name, " ", "_")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_report.pdf"`, safeTitle))

		if err := tmpl.Execute(w, data); err != nil {
			return
		}
	}
}
