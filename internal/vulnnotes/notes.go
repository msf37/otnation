// Package vulnnotes provides hardcoded vulnerability notes and red-team tips
// for well-known ports and services encountered during OT/SCADA reconnaissance.
package vulnnotes

// Note holds risk context and red-team intelligence for a specific port/service.
type Note struct {
	Port        int      `json:"port"`
	Service     string   `json:"service"`
	Risk        string   `json:"risk"` // critical, high, medium, low
	Notes       string   `json:"notes"`
	RedTeamTips []string `json:"red_team_tips"`
	References  []string `json:"references"`
}

// noteTable is the static lookup table indexed by port number.
var noteTable = map[int]Note{
	// OT/ICS Protocols
	502: {
		Port:    502,
		Service: "Modbus TCP",
		Risk:    "critical",
		Notes:   "Modbus TCP provides no authentication or encryption. An attacker with network access can read/write coils and registers directly, issue control commands, and modify PLC logic. Exposure on public internet is an immediate critical finding.",
		RedTeamTips: []string{
			"Use mbtget or pymodbus to enumerate coils, discrete inputs, holding registers, and input registers",
			"FC43 (0x2B) Read Device Identification returns vendor/model without authentication",
			"Write to holding registers (FC16) or coils (FC05) to test for write access",
			"Scan for Modbus on non-standard ports (e.g. 5020, 5502) — some devices run on alternate ports",
			"Replay captured legitimate commands to reproduce control actions",
		},
		References: []string{
			"https://www.cisa.gov/sites/default/files/recommended_practices/final-RP-ics-improving-industrial-control-systems-cybersecurity-with-defense-in-depth-strategies.pdf",
			"https://www.digitalbond.com/tools/basecamp/modbus/",
		},
	},
	102: {
		Port:    102,
		Service: "Siemens S7 / ISO-TSAP",
		Risk:    "critical",
		Notes:   "Port 102 hosts the Siemens S7 protocol (ISO-TSAP/S7comm). No authentication is required on older devices. An attacker can enumerate the CPU state, upload/download blocks, and start/stop the PLC.",
		RedTeamTips: []string{
			"Use snap7 or s7-scan (Nmap NSE script s7-info) to fingerprint the PLC model, firmware, and CPU state",
			"S7comm-plus (used in S7-1200/1500) adds a proprietary crypto layer — may still be brute-forceable",
			"COTP CR followed by S7 Setup yields PDU negotiation confirming S7 service is active",
			"Try 'stop CPU' and 'start CPU' commands with snap7 if no authentication is configured",
			"CVE-2019-13945: Siemens S7 authentication bypass on some firmware versions",
		},
		References: []string{
			"https://www.siemens.com/cert/en/advisories.htm",
			"https://github.com/stamparm/s7scan",
		},
	},
	47808: {
		Port:    47808,
		Service: "BACnet",
		Risk:    "high",
		Notes:   "BACnet (Building Automation and Control Networks) typically runs over UDP/47808. The WhoIs broadcast reveals all devices on the network. Read/write property access is usually unauthenticated on older implementations.",
		RedTeamTips: []string{
			"Send a WhoIs broadcast to enumerate all BACnet devices on the segment",
			"Use bacnet-stack or BACpypes to enumerate device objects and properties",
			"ReadProperty on analog/binary output objects can reveal setpoints and status",
			"WriteProperty can alter HVAC setpoints, lighting, and access controls in building systems",
			"CVE-2021-28485: BACnet stack buffer overflow in some implementations",
		},
		References: []string{
			"https://www.ashrae.org/technical-resources/standards-and-guidelines/reading-ashrae-standards/bacnet",
			"https://www.digitalbond.com/tools/basecamp/bacnet/",
		},
	},
	20000: {
		Port:    20000,
		Service: "DNP3",
		Risk:    "critical",
		Notes:   "DNP3 (Distributed Network Protocol 3) is widely used in power grids and water systems. Baseline DNP3 has no authentication (Secure Authentication v5 is optional). Attackers can issue control commands to RTUs and IEDs.",
		RedTeamTips: []string{
			"Use DNP3 fuzzer from Aegis or scapy-dnp3 to craft and replay commands",
			"Data-Link Layer broadcast (DA=0xFFFF) reveals all DNP3 devices on segment",
			"Direct Operate (FC 0x03) and Direct Operate No Ack (FC 0x04) allow unauthenticated actuation",
			"Monitor for unsolicited responses (FC 0x82) to infer operational state",
			"CVE-2013-2799: DNP3 denial of service in many SCADA products",
		},
		References: []string{
			"https://www.cisa.gov/uscert/ics/alerts/ICS-ALERT-14-176-02A",
			"https://dnp.org/AboutUs/DNP3StandardExt.aspx",
		},
	},
	44818: {
		Port:    44818,
		Service: "EtherNet/IP (CIP)",
		Risk:    "critical",
		Notes:   "EtherNet/IP uses the Common Industrial Protocol (CIP) over TCP/44818. ListIdentity (command 0x63) enumerates all devices. CIP messaging allows reading/writing tags, modifying parameters, and issuing reset commands.",
		RedTeamTips: []string{
			"Send ListIdentity (0x63 00 00 00 ...) to enumerate devices without authentication",
			"Use cpppo or pycomm3 to browse all controller tags and I/O assemblies",
			"CIP Set_Attribute_Single can modify parameters on Allen-Bradley PLCs",
			"CVE-2012-6435: Rockwell Automation EtherNet/IP denial of service",
			"Module Reset (CIP service 0x05 to class 0x01) can perform unauthenticated resets on some devices",
		},
		References: []string{
			"https://www.odva.org/technology-standards/key-technologies/ethernet-ip/",
			"https://ics-cert.us-cert.gov/advisories/ICSA-12-240-01",
		},
	},
	4840: {
		Port:    4840,
		Service: "OPC-UA",
		Risk:    "high",
		Notes:   "OPC-UA (Unified Architecture) is the modern OPC standard. Misconfigurations include anonymous access, self-signed certificates, and exposing the discovery endpoint publicly.",
		RedTeamTips: []string{
			"Use opcua-client or python-opcua to connect with None security mode (no encryption/auth)",
			"GetEndpoints reveals all supported security policies — look for None or Basic128Rsa15",
			"Browse the address space to enumerate nodes, variables, and methods",
			"ReadNodes on process variables can reveal live operational data",
			"CVE-2021-27434: OPC Foundation OPC-UA .NET stack remote code execution",
		},
		References: []string{
			"https://opcfoundation.org/developer-tools/specifications-unified-architecture",
			"https://www.digitalbond.com/2012/11/01/what-is-opc-ua/",
		},
	},
	1911: {
		Port:    1911,
		Service: "Niagara Fox",
		Risk:    "critical",
		Notes:   "Niagara Fox (Tridium Niagara) is a widely deployed BAS/SCADA middleware. Port 1911 (Fox protocol) allows unauthenticated enumeration in older versions. Numerous critical CVEs exist for directory traversal and RCE.",
		RedTeamTips: []string{
			"Use fox-scanner to enumerate Niagara stations and modules",
			"CVE-2012-0228 and CVE-2012-0230: Tridium Niagara AX directory traversal — retrieve config.bog",
			"config.bog contains credentials in obfuscated form — decrypt with known tools",
			"Port 1911 may allow unauthenticated fox:// protocol access to live data",
			"Newer versions (N4) use HTTPS on 443/8443 — check for default credentials (admin/admin)",
		},
		References: []string{
			"https://ics-cert.us-cert.gov/advisories/ICSA-12-116-01",
			"https://www.tridium.com/en/product-updates/security",
		},
	},
	4911: {
		Port:    4911,
		Service: "Niagara Fox (SSL)",
		Risk:    "critical",
		Notes:   "Niagara Fox SSL (port 4911) is the encrypted variant of the Fox protocol. The same Niagara vulnerabilities apply — check for weak TLS configuration and default credentials.",
		RedTeamTips: []string{
			"Use fox-scanner with SSL flag to enumerate over 4911",
			"Check for self-signed certificates or expired certificates indicating poor maintenance",
			"Try default credentials: admin/admin, supervisor/supervisor, operator/operator",
			"CVE-2017-16744 and CVE-2017-16748: Tridium Niagara N4 credential exposure",
		},
		References: []string{
			"https://ics-cert.us-cert.gov/advisories/ICSA-17-325-02",
		},
	},
	9600: {
		Port:    9600,
		Service: "Omron FINS",
		Risk:    "critical",
		Notes:   "Omron FINS (Factory Interface Network Service) provides unauthenticated access to PLC memory, I/O areas, and program data. Remote memory read/write is possible.",
		RedTeamTips: []string{
			"Use fins.py or Metasploit auxiliary/scanner/scada/omron_fins_tcp_scan",
			"FINS command 0101 reads memory — try DM area, CIO area",
			"FINS command 0102 writes memory areas without authentication",
			"CPU Unit Status Read (0601) reveals operating mode",
			"Try CPU mode change to PROGRAM mode to halt execution",
		},
		References: []string{
			"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13555",
			"https://www.us-cert.gov/ics/advisories/ICSA-19-192-01",
		},
	},
	2404: {
		Port:    2404,
		Service: "IEC 60870-5-104 (IEC 104)",
		Risk:    "critical",
		Notes:   "IEC 104 is used in power grid SCADA for telecontrol. No authentication in baseline standard. An attacker can send ASDU type commands to trip circuit breakers and control transmission infrastructure.",
		RedTeamTips: []string{
			"Send STARTDT (0x68 0x04 0x07 0x00 0x00 0x00) to initiate a data transfer session",
			"Use iec104-tools or scapy to enumerate information objects (ASDU)",
			"Type C_SC_NA_1 (0x2D) and C_DC_NA_1 (0x2E) are single/double command ASDUs",
			"Monitor spontaneous transmissions (cause of transmission = 3) to learn real-time state",
			"CVE-2020-10640: Triangle MicroWorks SCADA Data Gateway IEC 104 buffer overflow",
		},
		References: []string{
			"https://www.iec.ch/dyn/www/f?p=103:38:0::::FSP_ORG_ID,FSP_LANG_ID:1228,25",
			"https://www.cisa.gov/uscert/ics/advisories/ICSA-20-168-01",
		},
	},
	// IT Protocols
	21: {
		Port:    21,
		Service: "FTP",
		Risk:    "high",
		Notes:   "FTP transmits credentials and data in cleartext. Anonymous login may be enabled. Active FTP traverses NAT poorly and can be exploited for port scanning (FTP bounce).",
		RedTeamTips: []string{
			"Test anonymous login: ftp <ip> with username 'anonymous'",
			"Brute-force with hydra: hydra -L users.txt -P passwords.txt ftp://<ip>",
			"Check for writable directories to upload webshells or malware",
			"Use FTP bounce (PORT command abuse) to scan internal hosts",
			"Capture credentials with Wireshark/tcpdump on the same network segment",
		},
		References: []string{
			"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
		},
	},
	22: {
		Port:    22,
		Service: "SSH",
		Risk:    "medium",
		Notes:   "SSH is encrypted but exposed SSH is a brute-force target. Weak keys, outdated algorithms (diffie-hellman-group1-sha1, arcfour), and default credentials are common issues on OT devices.",
		RedTeamTips: []string{
			"Run ssh-audit to check cipher suites and key exchange algorithms",
			"Brute-force with hydra or medusa using common OT credentials (admin, root, operator)",
			"Check for SSH version 1 which is cryptographically broken",
			"Look for authorized_keys left by previous engagements or misconfiguration",
			"Test user enumeration (some OpenSSH versions leak valid usernames via timing)",
		},
		References: []string{
			"https://ssh-audit.com/",
			"https://www.ssh.com/academy/ssh/security",
		},
	},
	23: {
		Port:    23,
		Service: "Telnet",
		Risk:    "critical",
		Notes:   "Telnet transmits all data including credentials in cleartext. Any network observer can capture sessions. OT devices often have Telnet enabled with default or no credentials.",
		RedTeamTips: []string{
			"Capture credentials with Wireshark on the same segment",
			"Try default credentials: admin/admin, root/root, cisco/cisco, empty password",
			"Brute-force with hydra: hydra -L users.txt -P pass.txt telnet://<ip>",
			"Some PLCs and HMIs expose Telnet for configuration — check for undocumented commands",
			"CVE-2020-25159: Many Moxa devices expose Telnet with default credentials",
		},
		References: []string{
			"https://cwe.mitre.org/data/definitions/319.html",
		},
	},
	25: {
		Port:    25,
		Service: "SMTP",
		Risk:    "medium",
		Notes:   "Exposed SMTP may allow open relay (sending email through the server without authentication), which facilitates phishing and spam campaigns. Also used for reconnaissance via VRFY/EXPN.",
		RedTeamTips: []string{
			"Test for open relay: HELO test; MAIL FROM: attacker@evil.com; RCPT TO: victim@target.com",
			"Enumerate users with VRFY command: VRFY admin",
			"Check for NTLM authentication disclosure with AUTH NTLM",
			"Test for mail injection if SMTP form exists in web app",
		},
		References: []string{
			"https://www.spamhaus.org/pbl/",
		},
	},
	80: {
		Port:    80,
		Service: "HTTP",
		Risk:    "medium",
		Notes:   "HTTP transmits data in cleartext. OT HMIs and configuration interfaces are often served over plain HTTP with default credentials. Exposed admin interfaces are a critical risk.",
		RedTeamTips: []string{
			"Check for default credentials on HMI web interfaces (admin/admin, operator/operator)",
			"Run gobuster or ffuf to discover hidden paths (/admin, /config, /api, /manage)",
			"Check for path traversal: ../../etc/passwd or ../../../config/config.xml",
			"Test for SQL injection on any login forms",
			"Check HTTP response headers for server version disclosure (Server: header)",
		},
		References: []string{
			"https://owasp.org/www-project-top-ten/",
		},
	},
	8080: {
		Port:    8080,
		Service: "HTTP Alternate",
		Risk:    "medium",
		Notes:   "Common alternate HTTP port for management interfaces, reverse proxies, and development servers. Often less hardened than port 80.",
		RedTeamTips: []string{
			"Check for management interfaces (Jenkins, Tomcat Manager, Spring Boot Actuator)",
			"Try default Tomcat credentials: tomcat/tomcat, admin/admin",
			"Test for exposed actuator endpoints: /actuator, /actuator/env, /actuator/heapdump",
			"Check for SSRF via proxy parameters",
		},
		References: []string{
			"https://owasp.org/www-project-top-ten/",
		},
	},
	443: {
		Port:    443,
		Service: "HTTPS",
		Risk:    "low",
		Notes:   "HTTPS encrypts traffic but weak TLS configuration, expired certificates, or default credentials remain exploitable. OT HTTPS interfaces may run outdated TLS versions.",
		RedTeamTips: []string{
			"Run testssl.sh or sslscan to enumerate cipher suites and TLS versions",
			"Check for POODLE (SSLv3), BEAST (TLS 1.0), FREAK, Logjam vulnerabilities",
			"Test for certificate CN/SAN mismatch or self-signed certificates",
			"Check HSTS header and HSTS preload list inclusion",
			"Try subdomain takeover if certificate covers wildcard *.example.com",
		},
		References: []string{
			"https://testssl.sh/",
			"https://ssl-config.mozilla.org/",
		},
	},
	3389: {
		Port:    3389,
		Service: "RDP",
		Risk:    "critical",
		Notes:   "Exposed RDP is one of the most commonly exploited services. BlueKeep (CVE-2019-0708), DejaBlue, and numerous authentication bypass vulnerabilities have been discovered. Brute force and credential stuffing are trivially easy.",
		RedTeamTips: []string{
			"Test for BlueKeep (CVE-2019-0708) with Metasploit module exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
			"Brute-force with crowbar or hydra: hydra -L users.txt -P pass.txt rdp://<ip>",
			"Check NLA (Network Level Authentication) — if disabled, credentials can be captured pre-auth",
			"Try pass-the-hash or Kerberos ticket attacks if domain credentials are obtained",
			"CVE-2019-0708 (BlueKeep), CVE-2019-1181/1182 (DejaBlue) — check for unpatched systems",
		},
		References: []string{
			"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708",
			"https://www.cisa.gov/uscert/ncas/alerts/aa19-168a",
		},
	},
	5900: {
		Port:    5900,
		Service: "VNC",
		Risk:    "critical",
		Notes:   "VNC provides remote desktop access. Many deployments have no authentication or use weak passwords. Cleartext authentication variants (VNC auth) transmit challenge-response that can be cracked offline.",
		RedTeamTips: []string{
			"Try null authentication (no password) — many embedded devices allow this",
			"Brute-force with hydra: hydra -P passwords.txt vnc://<ip>",
			"Capture VNC challenge-response and crack offline with vnccrack",
			"Check for VNC Version 3.3 which has weak DES-based authentication",
			"Some industrial HMIs expose VNC for remote viewing with no auth",
		},
		References: []string{
			"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15694",
		},
	},
	161: {
		Port:    161,
		Service: "SNMP",
		Risk:    "high",
		Notes:   "SNMP v1/v2c uses community strings as cleartext passwords. Default community string 'public' is read-only; 'private' gives write access. SNMP v1/v2c traffic can be sniffed from the network.",
		RedTeamTips: []string{
			"Enumerate with community strings: snmpwalk -v2c -c public <ip>",
			"Try write community string 'private': snmpset -v2c -c private <ip> <oid> <type> <value>",
			"Enumerate MIB tree for software versions, routing tables, and ARP caches",
			"Use onesixtyone for fast community string brute-force",
			"CVE-2017-12278: SNMP write access can modify Cisco device configurations",
		},
		References: []string{
			"https://www.cisa.gov/uscert/ncas/alerts/TA17-293A",
		},
	},
	445: {
		Port:    445,
		Service: "SMB",
		Risk:    "critical",
		Notes:   "SMB exposed to the internet enables EternalBlue (MS17-010), WannaCry, and pass-the-hash attacks. Even internally, SMB misconfigurations facilitate lateral movement.",
		RedTeamTips: []string{
			"Test for MS17-010 (EternalBlue): use Metasploit exploit/windows/smb/ms17_010_eternalblue",
			"Enumerate shares: smbclient -L //<ip>/ -N or nmap --script smb-enum-shares",
			"Check for null session: smbclient //<ip>/IPC$ -N",
			"Try pass-the-hash with impacket-psexec or crackmapexec",
			"CVE-2017-0144 (EternalBlue) — one of the most critical Windows vulnerabilities ever found",
		},
		References: []string{
			"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144",
			"https://www.cisa.gov/uscert/ncas/alerts/ta17-132a",
		},
	},
	1433: {
		Port:    1433,
		Service: "MSSQL",
		Risk:    "high",
		Notes:   "Exposed MSSQL allows SQL injection, brute force attacks on SA account, and potential xp_cmdshell execution for OS command injection. Historian databases frequently use MSSQL.",
		RedTeamTips: []string{
			"Brute-force SA account: hydra -l sa -P passwords.txt mssql://<ip>",
			"Check for xp_cmdshell enabled: EXEC xp_cmdshell 'whoami'",
			"Use impacket-mssqlclient for interactive exploitation",
			"Enumerate linked servers: SELECT * FROM sys.servers",
			"MSSQL running as SYSTEM is common — enables full OS compromise",
		},
		References: []string{
			"https://www.mssqltips.com/sqlservertutorial/196/securing-sql-server/",
		},
	},
	3306: {
		Port:    3306,
		Service: "MySQL",
		Risk:    "high",
		Notes:   "Exposed MySQL allows brute force on root/admin accounts, data exfiltration, and potentially OS command execution via SELECT ... INTO OUTFILE.",
		RedTeamTips: []string{
			"Brute-force root: hydra -l root -P passwords.txt mysql://<ip>",
			"Check for SELECT INTO OUTFILE to write webshells",
			"Enumerate databases: SHOW DATABASES; and users: SELECT * FROM mysql.user;",
			"Check for LOAD DATA LOCAL INFILE enabled (client-side file read)",
			"CVE-2012-2122: MySQL authentication bypass with incorrect password in some versions",
		},
		References: []string{
			"https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html",
		},
	},
	6379: {
		Port:    6379,
		Service: "Redis",
		Risk:    "critical",
		Notes:   "Redis with no authentication and bound to 0.0.0.0 allows full data access and often OS command execution via CONFIG SET dir/dbfilename to write SSH keys or cron jobs.",
		RedTeamTips: []string{
			"Connect without auth: redis-cli -h <ip> ping",
			"Dump all keys: redis-cli -h <ip> --scan",
			"Write SSH key: CONFIG SET dir /root/.ssh; CONFIG SET dbfilename authorized_keys; SET key '\\nssh-rsa AAAA...\\n'; BGSAVE",
			"Write cron job for reverse shell: CONFIG SET dir /var/spool/cron/crontabs; ...",
			"CVE-2022-0543: Lua sandbox escape in Redis on Debian/Ubuntu",
		},
		References: []string{
			"https://redis.io/docs/manual/security/",
		},
	},
	27017: {
		Port:    27017,
		Service: "MongoDB",
		Risk:    "critical",
		Notes:   "MongoDB with authentication disabled allows full read/write access to all databases. Ransomware groups have repeatedly wiped exposed MongoDB instances.",
		RedTeamTips: []string{
			"Connect without auth: mongosh --host <ip> --port 27017",
			"List databases: show dbs",
			"Dump collections: db.getCollectionNames(); db.<collection>.find().limit(10)",
			"Check for admin user with empty password",
			"CVE-2021-20328: MongoDB arbitrary file read in some server versions",
		},
		References: []string{
			"https://www.mongodb.com/docs/manual/security/",
		},
	},
	9200: {
		Port:    9200,
		Service: "Elasticsearch",
		Risk:    "critical",
		Notes:   "Elasticsearch without authentication exposes all indexed data. Attackers have massively exfiltrated sensitive data from exposed Elasticsearch clusters.",
		RedTeamTips: []string{
			"Check health: curl http://<ip>:9200/_cluster/health",
			"List indices: curl http://<ip>:9200/_cat/indices",
			"Dump data: curl http://<ip>:9200/<index>/_search?size=100",
			"Check for X-Pack security: curl http://<ip>:9200/_xpack/security/_authenticate",
			"CVE-2019-7614: Elasticsearch CSRF and information disclosure",
		},
		References: []string{
			"https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html",
		},
	},
	11211: {
		Port:    11211,
		Service: "Memcached",
		Risk:    "critical",
		Notes:   "Memcached has no authentication and is frequently exposed. It has been abused for massive DDoS amplification attacks (UDP amplification factor ~50000x) and exposes all cached application data.",
		RedTeamTips: []string{
			"Connect and dump stats: echo 'stats' | nc -q1 <ip> 11211",
			"List all keys: echo 'stats items' | nc -q1 <ip> 11211",
			"Read cached values: echo 'get <key>' | nc -q1 <ip> 11211",
			"UDP port 11211 can be used for DDoS amplification — test with caution",
			"CVE-2018-1000115: Memcached UDP amplification vulnerability",
		},
		References: []string{
			"https://www.cisa.gov/uscert/ncas/alerts/TA18-060A",
		},
	},
}

// GetNotes returns the Note for a given port, or nil if no entry exists.
func GetNotes(port int) *Note {
	if n, ok := noteTable[port]; ok {
		return &n
	}
	return nil
}

// GetAllNotes returns all notes in the table as a slice.
func GetAllNotes() []Note {
	notes := make([]Note, 0, len(noteTable))
	for _, n := range noteTable {
		notes = append(notes, n)
	}
	return notes
}
