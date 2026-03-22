// Package models defines all database-mapped Go structs for the platform.
// Types use pgx-compatible representations wherever possible.
package models

import (
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Enum types
// ---------------------------------------------------------------------------

// SeedType classifies the kind of seed input supplied by a user.
type SeedType string

const (
	SeedTypeIP     SeedType = "ip"
	SeedTypeCIDR   SeedType = "cidr"
	SeedTypeDomain SeedType = "domain"
)

// AssetType classifies a discovered asset.
type AssetType string

const (
	AssetTypeIP        AssetType = "ip"
	AssetTypeDomain    AssetType = "domain"
	AssetTypeSubdomain AssetType = "subdomain"
	AssetTypeEndpoint  AssetType = "endpoint"
)

// EnrichmentSource indicates where enrichment data originated.
type EnrichmentSource string

const (
	EnrichmentSourceInternal       EnrichmentSource = "internal"
	EnrichmentSourceShodan         EnrichmentSource = "shodan"
	EnrichmentSourceManual         EnrichmentSource = "manual"
	EnrichmentSourceSecurityTrails EnrichmentSource = "securitytrails"
	EnrichmentSourceCrtSh          EnrichmentSource = "crtsh"
	EnrichmentSourceHTTPProbe      EnrichmentSource = "http_probe"
	EnrichmentSourceSNMP           EnrichmentSource = "snmp"
	EnrichmentSourceOTProbe        EnrichmentSource = "ot_probe"
	EnrichmentSourceBGP            EnrichmentSource = "bgp"
	EnrichmentSourceIPWhois        EnrichmentSource = "ip_whois"
	EnrichmentSourceCVECorrelation EnrichmentSource = "cve_correlation"
	EnrichmentSourceVulnNotes      EnrichmentSource = "vuln_notes"
	EnrichmentSourceIEC61850       EnrichmentSource = "iec61850"
	EnrichmentSourceHistorian      EnrichmentSource = "historian"
	EnrichmentSourceHMI            EnrichmentSource = "hmi"
	EnrichmentSourceICSCert        EnrichmentSource = "icscert"
	EnrichmentSourceIEC104         EnrichmentSource = "iec104"
	EnrichmentSourceModbusDeep     EnrichmentSource = "modbus_deep"
	EnrichmentSourceDNP3Deep       EnrichmentSource = "dnp3_deep"
	EnrichmentSourceICCP           EnrichmentSource = "iccp"
	EnrichmentSourceEtherNetIPDeep EnrichmentSource = "enip_deep"
	EnrichmentSourceProfinet       EnrichmentSource = "profinet"
	EnrichmentSourceOPCUA          EnrichmentSource = "opcua"
	EnrichmentSourceDefaultCreds   EnrichmentSource = "default_creds"
	EnrichmentSourceCensys         EnrichmentSource = "censys"
)

// SeverityLevel classifies the risk level of a finding.
type SeverityLevel string

const (
	SeverityCritical      SeverityLevel = "critical"
	SeverityHigh          SeverityLevel = "high"
	SeverityMedium        SeverityLevel = "medium"
	SeverityLow           SeverityLevel = "low"
	SeverityInformational SeverityLevel = "informational"
)

// RunStatus represents the lifecycle state of a discovery run.
type RunStatus string

const (
	RunStatusPending   RunStatus = "pending"
	RunStatusRunning   RunStatus = "running"
	RunStatusCompleted RunStatus = "completed"
	RunStatusFailed    RunStatus = "failed"
)

// JobStatus represents the lifecycle state of a single background job.
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusRetrying  JobStatus = "retrying"
)

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

// Identity represents a monitored organization or target.
// Corresponds to the identities table.
type Identity struct {
	ID        uuid.UUID `db:"id"         json:"id"`
	Name      string    `db:"name"       json:"name"`
	OrgName   string    `db:"org_name"   json:"org_name"`
	Notes     string    `db:"notes"      json:"notes,omitempty"`
	Tags      []byte    `db:"tags"       json:"tags"`      // raw JSONB
	Sector    string    `db:"sector"     json:"sector,omitempty"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

// Seed stores the original user-supplied input (IP, CIDR, or domain).
// Corresponds to the seeds table.
type Seed struct {
	ID         uuid.UUID `db:"id"          json:"id"`
	IdentityID uuid.UUID `db:"identity_id" json:"identity_id"`
	Type       SeedType  `db:"type"        json:"type"`
	Value      string    `db:"value"       json:"value"`
	CreatedAt  time.Time `db:"created_at"  json:"created_at"`
}

// ---------------------------------------------------------------------------
// Asset
// ---------------------------------------------------------------------------

// Asset represents a discovered object such as an IP, domain, subdomain,
// or web endpoint.
// Corresponds to the assets table.
type Asset struct {
	ID          uuid.UUID `db:"id"           json:"id"`
	IdentityID  uuid.UUID `db:"identity_id"  json:"identity_id"`
	Type        AssetType `db:"type"         json:"type"`
	Value       string    `db:"value"        json:"value"`
	Provenance  string    `db:"provenance"   json:"provenance"`
	IsPublic    bool      `db:"is_public"    json:"is_public"`
	IsCloud     bool      `db:"is_cloud"     json:"is_cloud"`
	CountryCode string    `db:"country_code" json:"country_code,omitempty"`
	ASN         *int64    `db:"asn"          json:"asn,omitempty"`
	ASNOrg      string    `db:"asn_org"      json:"asn_org,omitempty"`
	ReverseDNS  string    `db:"reverse_dns"  json:"reverse_dns,omitempty"`
	CreatedAt   time.Time `db:"created_at"   json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"   json:"updated_at"`
}

// Provenance constants describe where an asset was discovered.
const (
	ProvenanceUserInput       = "user_input"
	ProvenanceDNS             = "dns"
	ProvenanceSubnetExpansion = "subnet_expansion"
	ProvenanceCrawl           = "crawl"
	ProvenanceExternalEnrich  = "external_enrichment"
	ProvenanceUnknown         = "unknown"
)

// ---------------------------------------------------------------------------
// DNSRecord
// ---------------------------------------------------------------------------

// DNSRecord stores a resolved DNS entry and its relationship to an asset.
// Corresponds to the dns_records table.
type DNSRecord struct {
	ID         uuid.UUID `db:"id"          json:"id"`
	IdentityID uuid.UUID `db:"identity_id" json:"identity_id"`
	AssetID    uuid.UUID `db:"asset_id"    json:"asset_id"`
	RecordType string    `db:"record_type" json:"record_type"` // A, AAAA, CNAME, etc.
	Name       string    `db:"name"        json:"name"`
	Value      string    `db:"value"       json:"value"`
	ResolvedIP string    `db:"resolved_ip" json:"resolved_ip,omitempty"`
	CreatedAt  time.Time `db:"created_at"  json:"created_at"`
}

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

// ScanResult stores the outcome of a port scan against a single asset/port.
// Corresponds to the scan_results table.
type ScanResult struct {
	ID              uuid.UUID `db:"id"               json:"id"`
	AssetID         uuid.UUID `db:"asset_id"         json:"asset_id"`
	IdentityID      uuid.UUID `db:"identity_id"      json:"identity_id"`
	Port            int       `db:"port"             json:"port"`
	Protocol        string    `db:"protocol"         json:"protocol"`
	ServiceName     string    `db:"service_name"     json:"service_name,omitempty"`
	Banner          string    `db:"banner"           json:"banner,omitempty"`
	ServiceCategory string    `db:"service_category" json:"service_category,omitempty"`
	Confidence      float64   `db:"confidence"       json:"confidence"`
	RawResponse     []byte    `db:"raw_response"     json:"raw_response,omitempty"`
	ScannedAt       time.Time `db:"scanned_at"       json:"scanned_at"`
	CreatedAt       time.Time `db:"created_at"       json:"created_at"`
}

// ServiceCategory constants classify the nature of a detected service.
const (
	ServiceCategoryIndustrialProtocol = "industrial_protocol"
	ServiceCategoryRemoteAccess       = "remote_access"
	ServiceCategoryWebInterface       = "web_interface"
	ServiceCategoryVPN                = "vpn_gateway"
	ServiceCategoryDatabase           = "database"
	ServiceCategoryGenericIT          = "generic_it"
	ServiceCategoryUnknown            = "unknown"
)

// ---------------------------------------------------------------------------
// EnrichmentRecord
// ---------------------------------------------------------------------------

// EnrichmentRecord stores metadata enrichment data for an asset from any
// supported source (internal, Shodan, manual).
// Corresponds to the enrichment_records table.
type EnrichmentRecord struct {
	ID        uuid.UUID        `db:"id"         json:"id"`
	AssetID   uuid.UUID        `db:"asset_id"   json:"asset_id"`
	Source    EnrichmentSource `db:"source"     json:"source"`
	Data      []byte           `db:"data"       json:"data"` // raw JSONB
	CreatedAt time.Time        `db:"created_at" json:"created_at"`
	UpdatedAt time.Time        `db:"updated_at" json:"updated_at"`
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

// Finding represents a detected vulnerability, exposure, or security issue
// associated with an asset.
// Corresponds to the findings table.
type Finding struct {
	ID           uuid.UUID      `db:"id"             json:"id"`
	IdentityID   uuid.UUID      `db:"identity_id"    json:"identity_id"`
	AssetID      uuid.UUID      `db:"asset_id"       json:"asset_id"`
	ScanResultID *uuid.UUID     `db:"scan_result_id" json:"scan_result_id,omitempty"` // nullable FK
	Title        string         `db:"title"          json:"title"`
	Description  string         `db:"description"    json:"description,omitempty"`
	Severity     SeverityLevel  `db:"severity"       json:"severity"`
	Category     string         `db:"category"       json:"category,omitempty"`
	Vendor       string         `db:"vendor"         json:"vendor,omitempty"`
	Protocol     string         `db:"protocol"       json:"protocol,omitempty"`
	Evidence     []byte         `db:"evidence"       json:"evidence"`     // raw JSONB
	AttackTTPs   []byte         `db:"attack_ttps"    json:"attack_ttps"`  // raw JSONB
	CreatedAt    time.Time      `db:"created_at"     json:"created_at"`
	UpdatedAt    time.Time      `db:"updated_at"     json:"updated_at"`
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

// Run represents one complete execution of a discovery and scanning workflow.
// Corresponds to the runs table.
type Run struct {
	ID          uuid.UUID  `db:"id"           json:"id"`
	IdentityID  uuid.UUID  `db:"identity_id"  json:"identity_id"`
	Status      RunStatus  `db:"status"       json:"status"`
	StartedAt   *time.Time `db:"started_at"   json:"started_at,omitempty"`
	EndedAt     *time.Time `db:"ended_at"     json:"ended_at,omitempty"`
	TriggeredBy string     `db:"triggered_by" json:"triggered_by"`
	Stats       []byte     `db:"stats"        json:"stats"` // raw JSONB
	CreatedAt   time.Time  `db:"created_at"   json:"created_at"`
}

// ---------------------------------------------------------------------------
// Job
// ---------------------------------------------------------------------------

// Job represents a single unit of work within a Run, processed by workers.
// Corresponds to the jobs table.
type Job struct {
	ID          uuid.UUID  `db:"id"           json:"id"`
	RunID       uuid.UUID  `db:"run_id"       json:"run_id"`
	Type        string     `db:"type"         json:"type"`
	Status      JobStatus  `db:"status"       json:"status"`
	Payload     []byte     `db:"payload"      json:"payload"` // raw JSONB
	Attempts    int        `db:"attempts"     json:"attempts"`
	MaxAttempts int        `db:"max_attempts" json:"max_attempts"`
	Error       string     `db:"error"        json:"error,omitempty"`
	CreatedAt   time.Time  `db:"created_at"   json:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at"   json:"updated_at"`
	StartedAt   *time.Time `db:"started_at"   json:"started_at,omitempty"`
	EndedAt     *time.Time `db:"ended_at"     json:"ended_at,omitempty"`
}

// JobType constants enumerate the kinds of background jobs the platform runs.
const (
	JobTypeDiscoveryRun      = "discovery_run"
	JobTypeDomainEnumeration = "domain_enumeration"
	JobTypeDNSResolution     = "dns_resolution"
	JobTypeIPEnrichment      = "ip_enrichment"
	JobTypeCrawl             = "crawl"
	JobTypeScan              = "scan"
	JobTypeAnalysis          = "analysis"
	JobTypeShodanEnrichment  = "shodan_enrichment"
)

// ---------------------------------------------------------------------------
// TLSScanResult
// ---------------------------------------------------------------------------

// TLSScanResult holds the outcome of a TLS certificate and protocol scan
// for a domain or subdomain asset.
// Corresponds to the tls_scan_results table.
type TLSScanResult struct {
	ID              uuid.UUID  `db:"id"               json:"id"`
	AssetID         uuid.UUID  `db:"asset_id"         json:"asset_id"`
	IdentityID      uuid.UUID  `db:"identity_id"      json:"identity_id"`
	ScannedAt       time.Time  `db:"scanned_at"       json:"scanned_at"`
	CommonName      string     `db:"common_name"      json:"common_name"`
	Issuer          string     `db:"issuer"           json:"issuer"`
	SANs            []byte     `db:"sans"             json:"sans"`           // JSONB []string
	NotBefore       *time.Time `db:"not_before"       json:"not_before"`
	NotAfter        *time.Time `db:"not_after"        json:"not_after"`
	DaysUntilExpiry *int       `db:"days_until_expiry" json:"days_until_expiry"`
	TLSVersion      string     `db:"tls_version"      json:"tls_version"`
	CipherSuite     string     `db:"cipher_suite"     json:"cipher_suite"`
	KeyAlgorithm    string     `db:"key_algorithm"    json:"key_algorithm"`
	KeySize         int        `db:"key_size"         json:"key_size"`
	SignatureAlgo   string     `db:"signature_algo"   json:"signature_algo"`
	Grade           string     `db:"grade"            json:"grade"`
	Issues          []byte     `db:"issues"           json:"issues"`         // JSONB []TLSIssue
	ErrorMsg        string     `db:"error_msg"        json:"error_msg"`
}

// ---------------------------------------------------------------------------
// AuditLog
// ---------------------------------------------------------------------------

// NERCCIPClassification stores NERC CIP asset classification data.
type NERCCIPClassification struct {
	BCSAsset     bool     `json:"bcs_asset"`     // Bulk Electric System asset
	AssetType    string   `json:"asset_type"`    // "Control Center", "Substation", "Generation", "Transmission"
	ImpactRating string   `json:"impact_rating"` // "High", "Medium", "Low", "Not BES"
	ESPName      string   `json:"esp_name"`      // Electronic Security Perimeter name
	Zone         string   `json:"zone"`          // IEC 62443 zone: "Safety", "Control", "Operations", "Enterprise"
	CIPStandards []string `json:"cip_standards"` // e.g. ["CIP-002", "CIP-005", "CIP-007"]
	Notes        string   `json:"notes"`
}

// ---------------------------------------------------------------------------
// AuditLog
// ---------------------------------------------------------------------------

// ScanHistory records a snapshot of open ports from a port scan.
// Corresponds to the scan_history table.
type ScanHistory struct {
	ID        uuid.UUID `db:"id"         json:"id"`
	AssetID   uuid.UUID `db:"asset_id"   json:"asset_id"`
	ScanDate  time.Time `db:"scan_date"  json:"scan_date"`
	OpenPorts []byte    `db:"open_ports" json:"open_ports"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// AuditLog records every significant action taken in the platform for
// security and compliance purposes.
// Corresponds to the audit_logs table.
type AuditLog struct {
	ID         uuid.UUID `db:"id"          json:"id"`
	EntityType string    `db:"entity_type" json:"entity_type"`
	EntityID   uuid.UUID `db:"entity_id"   json:"entity_id"`
	Action     string    `db:"action"      json:"action"`
	Actor      string    `db:"actor"       json:"actor"`
	Details    []byte    `db:"details"     json:"details"` // raw JSONB
	CreatedAt  time.Time `db:"created_at"  json:"created_at"`
}
