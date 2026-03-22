# OT Nation — Operational Technology Security Platform

## Overview

OT Nation is a purpose-built security intelligence and exposure assessment platform for critical infrastructure organizations. It gives security teams, compliance officers, and red teams a single system to discover, inventory, scan, and assess the cybersecurity risk of their operational technology (OT) environments — power grids, substations, industrial control systems, and SCADA networks.

The platform is built around a core principle: **you cannot secure what you cannot see**. It automates the process of finding internet-facing industrial assets, probing them for known protocols, correlating vulnerabilities, and generating actionable findings — all from a web interface.

---

## The Problem It Solves

Operational Technology environments were designed for availability and reliability, not security. As these systems become increasingly connected, they create an attack surface that most organizations do not fully understand. The typical challenges are:

- No centralized inventory of internet-facing industrial assets
- OT-specific protocols (Modbus, DNP3, IEC 61850) are invisible to standard IT security tools
- Regulatory frameworks like NERC CIP require detailed asset classification that is difficult to maintain manually
- Threat intelligence from sources like Shodan and Censys is not automatically correlated with internal asset data
- Red teams lack a structured tool to enumerate and probe OT infrastructure at scale

OT Nation addresses all of these gaps in a single integrated platform.

---

## How It Works

The workflow is organized around **Identities** — each identity represents an organization or target scope. The user provides **Seeds** (IP addresses, CIDR ranges, or domain names) and the platform takes over from there.

### 1. Discovery

The platform expands seeds into individual assets. CIDR blocks are broken into individual IPs, domains are resolved, web pages are crawled for linked resources, and subdomains are enumerated. All discovered assets (IPs, domains, subdomains, endpoints) are stored and tracked.

### 2. Port Scanning

Assets are scanned across a curated list of OT and ICS-relevant ports — covering protocols like Modbus (502), DNP3 (20000), IEC 61850 (102), IEC 104 (2404), EtherNet/IP (44818), OPC-UA (4840), BACnet (47808), Siemens S7, Niagara Fox, Profinet, and more. Scan profiles (light, standard, deep) control depth and speed.

### 3. Protocol-Level Deep Scanning

Once an open port is found, the platform can run protocol-specific scanners that go beyond port detection. These scanners speak the actual industrial protocol and extract meaningful data:

| Scanner | Protocol | What It Extracts |
|---|---|---|
| IEC 61850 | MMS/ISO-TSAP | Device type, logical device names |
| IEC 104 | IEC 60870-5-104 | ASDU data objects, device type |
| Modbus Deep | Modbus TCP | Coils, registers (FC1–FC4) |
| DNP3 Deep | DNP3 | Data points, group/variation/index |
| EtherNet/IP | CIP | Rockwell/Allen-Bradley device info |
| OPC-UA | OPC-UA | Endpoint URLs, security policies |
| Profinet | DCP | Station name, vendor ID |
| ICCP/TASE.2 | ISO/ACSE | Control center data exchange detection |
| Default Credentials | HTTP/S | Vendor default password exposure |

### 4. Enrichment & Threat Intelligence

Assets are enriched from multiple external sources automatically:

- **Shodan & Censys** — passive internet scan data, service banners, geolocation
- **SecurityTrails** — historical DNS records and WHOIS
- **crt.sh** — certificate transparency logs
- **CISA ICS-CERT** — known advisories for industrial vendors
- **NIST NVD** — CVE correlation by service and banner
- **ExploitDB** — public exploit availability per CVE
- **BGP & IP WHOIS** — routing and ownership data

### 5. Findings Generation

The platform automatically generates security findings from scan results. Findings are categorized by severity (Critical, High, Medium, Low) and include evidence, MITRE ATT&CK for ICS technique mappings, vendor attribution, and protocol context. Examples include exposed IEDs, unauthenticated Modbus devices, default credentials found active, missing TLS, and IEC 62351 absence.

### 6. Compliance

Each asset can be classified against **NERC CIP** requirements, including BCS asset status, impact rating (High/Medium/Low), asset type, Electronic Security Perimeter assignment, and applicable CIP standards (CIP-002 through CIP-013). The platform also maps assets to **IEC 62443 zones** (Safety, Control, Operations, Enterprise).

### 7. Reporting & Export

- PDF security reports per identity
- JSON and CSV exports for assets and findings
- REST API for integration with SIEM, ticketing, or GRC platforms

---

## Platform Architecture

| Layer | Technology |
|---|---|
| Backend | Go 1.24 — compiled, statically typed, high performance |
| API | RESTful, 100+ endpoints, versioned under `/api/v1` |
| Database | PostgreSQL — 12+ tables, JSONB for flexible evidence storage |
| Frontend | Single-page web application (no framework, plain JS/CSS) |
| Background Jobs | Async worker queue for long-running scans and discovery |

The platform runs as a single binary with a configuration file. It has no external runtime dependencies beyond PostgreSQL.

---

## Key Numbers

| Metric | Count |
|---|---|
| OT protocol scanners | 9 |
| External intelligence sources | 12+ |
| API endpoints | 100+ |
| Database tables | 12 |
| Supported OT/ICS ports scanned | 15+ |
| Finding severity levels | 5 |
| Export formats | 4 (JSON, CSV, PDF, text) |
| Scan profiles | 3 (light, standard, deep) |

---

## API Endpoints

### Identities
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/identities` | Create identity |
| GET | `/api/v1/identities` | List identities |
| GET | `/api/v1/identities/{id}` | Get identity details |
| PUT | `/api/v1/identities/{id}` | Update identity |
| DELETE | `/api/v1/identities/{id}` | Delete identity |
| GET | `/api/v1/identities/{id}/stats` | Identity statistics |
| GET | `/api/v1/identities/{id}/report` | Text report |
| GET | `/api/v1/identities/{id}/report.pdf` | PDF report |

### Assets
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/identities/{id}/assets` | List assets |
| GET | `/api/v1/assets/{asset_id}` | Get asset |
| GET | `/api/v1/assets/{asset_id}/scan-results` | Scan results |
| GET | `/api/v1/assets/{asset_id}/findings` | Asset findings |
| GET | `/api/v1/assets/{asset_id}/history` | Scan history |
| POST | `/api/v1/assets/{asset_id}/port-scan` | Trigger port scan |
| POST | `/api/v1/assets/{asset_id}/auto-scan` | Auto scan chain |

### OT Protocol Scanners (GET = retrieve stored result, POST = run scan)
| Endpoint | Protocol |
|---|---|
| `/assets/{id}/iec61850` | IEC 61850 MMS |
| `/assets/{id}/iec104` | IEC 60870-5-104 |
| `/assets/{id}/modbus-deep` | Modbus FC1–FC4 |
| `/assets/{id}/dnp3-deep` | DNP3 Class 0 |
| `/assets/{id}/enip-deep` | EtherNet/IP CIP |
| `/assets/{id}/opcua` | OPC-UA |
| `/assets/{id}/profinet` | Profinet DCP |
| `/assets/{id}/iccp` | ICCP/TASE.2 |
| `/assets/{id}/default-creds` | Default Credentials |

### Enrichment (GET = retrieve, POST = trigger)
| Endpoint | Source |
|---|---|
| `/assets/{id}/deep-scan` | Shodan |
| `/assets/{id}/censys` | Censys |
| `/assets/{id}/securitytrails` | SecurityTrails |
| `/assets/{id}/crtsh` | crt.sh |
| `/assets/{id}/http-probe` | HTTP Probe |
| `/assets/{id}/snmp` | SNMP |
| `/assets/{id}/ot-probe` | OT Multi-probe |
| `/assets/{id}/bgp` | BGP |
| `/assets/{id}/ip-whois` | IP WHOIS |
| `/assets/{id}/cve-correlate` | NIST NVD |
| `/assets/{id}/historian` | Historian Detect |
| `/assets/{id}/hmi` | HMI Fingerprint |
| `/assets/{id}/icscert` | CISA ICS-CERT |

### Compliance
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/assets/{id}/nerc-cip` | Get NERC CIP classification |
| PUT | `/api/v1/assets/{id}/nerc-cip` | Set NERC CIP classification |

### Export
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/identities/{id}/export/assets.json` | Assets as JSON |
| GET | `/api/v1/identities/{id}/export/assets.csv` | Assets as CSV |
| GET | `/api/v1/identities/{id}/export/findings.json` | Findings as JSON |
| GET | `/api/v1/identities/{id}/export/findings.csv` | Findings as CSV |

---

## Database Schema

| Table | Description |
|---|---|
| `identities` | Target organizations with sector, tags, notes |
| `seeds` | User-supplied IPs, CIDRs, domains |
| `assets` | Discovered IPs, domains, subdomains, endpoints |
| `dns_records` | DNS resolution results per asset |
| `scan_results` | Port scan results with service fingerprinting |
| `enrichment_records` | External enrichment data (JSONB) |
| `findings` | Vulnerabilities and exposures with evidence |
| `runs` | Discovery/scan run execution records |
| `jobs` | Background worker jobs within a run |
| `tls_scan_results` | TLS certificate details per domain |
| `scan_history` | Historical open port snapshots |
| `audit_logs` | Action audit trail for compliance |

---

## Configuration

The platform is configured via a YAML file:

```yaml
server:
  host: 0.0.0.0
  port: 8080

database:
  dsn: postgres://otnation:otnation@localhost:5432/otnation?sslmode=disable

scanner:
  scada_ports: [102, 502, 20000, 44818, 47808, 4840, 1911, 9600, 2404, 4000, 20547, 38400]
  timeout_ms: 3000
  concurrency: 50
  rate_limit_per_sec: 100
  default_profile: standard   # light | standard | deep

dns:
  resolvers: ["8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"]

shodan:
  api_key: ""

security_trails:
  api_key: ""

censys:
  api_id: ""
  api_secret: ""
```

---

## Who Uses It

**Security Analysts** — Continuous monitoring of OT attack surface, new asset discovery, and change detection between scans.

**Red Teams / Penetration Testers** — Structured enumeration of OT targets, protocol-level probing, and credential testing with full audit trail.

**Compliance Officers** — NERC CIP asset classification, evidence collection for CIP-002 through CIP-013, and exportable records for auditors.

**Security Operations** — Automated scan chains, finding management, and integration-ready REST API for feeding results into SIEM or ticketing systems.

---

## Current Status

The platform is fully functional with all core modules implemented and integrated. The backend, all protocol scanners, the enrichment pipeline, the compliance module, and the web interface are operational. The system is running and actively being refined based on real-world testing against electricity sector infrastructure.
