package dns

// commonSubdomains is an expanded wordlist of subdomain prefixes used during enumeration.
// Includes general-purpose, IT infrastructure, OT/SCADA-specific, and common service names.
var commonSubdomains = []string{
	// General web
	"www", "web", "www2", "www3", "secure", "portal", "app", "apps",
	"mobile", "m", "static", "cdn", "assets", "media", "images", "img",
	"files", "downloads", "upload", "uploads", "api", "api2", "rest",
	"graphql", "backend", "frontend",

	// Email
	"mail", "mail2", "smtp", "pop", "pop3", "imap", "webmail", "mx",
	"exchange", "owa", "autodiscover", "mta",

	// Authentication / Identity
	"auth", "sso", "idp", "login", "accounts", "identity", "oauth",
	"saml", "ldap", "ad", "directory", "radius",

	// Network infrastructure
	"gateway", "gw", "router", "switch", "firewall", "fw", "proxy",
	"vpn", "vpn2", "remote", "rdp", "citrix", "jump", "jumphost",
	"bastion", "terminal", "ssh", "telnet", "ntp", "dns", "dns1",
	"dns2", "ns", "ns1", "ns2", "resolver",

	// IT management
	"admin", "administrator", "mgmt", "management", "console",
	"panel", "dashboard", "control", "config", "cfg", "setup",
	"helpdesk", "support", "it", "sysadmin", "ops", "devops",
	"netops", "noc", "soc",

	// Monitoring & logging
	"monitor", "monitoring", "nagios", "zabbix", "grafana", "kibana",
	"splunk", "elk", "elastic", "elasticsearch", "logstash", "logs",
	"syslog", "metrics", "prometheus", "alerting", "alerts",

	// Security
	"scan", "scanner", "vuln", "siem", "ids", "ips", "waf",
	"pentest", "security", "sec", "certs", "pki", "ca",

	// Databases
	"db", "db1", "db2", "database", "mysql", "postgres", "sql",
	"oracle", "mssql", "mongodb", "redis", "cache", "memcache",
	"elastic", "cassandra", "influx", "influxdb",

	// Storage / backup
	"storage", "nas", "san", "backup", "backups", "archive",
	"ftp", "sftp", "files", "share", "nfs", "smb",

	// Cloud / virtualization
	"cloud", "vm", "vms", "vsphere", "vcenter", "esxi", "hyper-v",
	"docker", "k8s", "kubernetes", "rancher", "openshift",

	// Dev / CI-CD
	"dev", "develop", "development", "staging", "stage", "test",
	"testing", "qa", "uat", "pre", "preprod", "beta", "alpha",
	"demo", "sandbox", "lab", "labs", "git", "gitlab", "github",
	"bitbucket", "jenkins", "ci", "cd", "build", "deploy",
	"sonar", "nexus", "artifactory", "jira", "confluence", "wiki",

	// Corporate
	"corp", "corporate", "intranet", "internal", "inside",
	"extranet", "partner", "partners", "vendor", "suppliers",
	"remote-access", "employees", "hr", "finance",

	// DMZ
	"dmz", "external", "public", "pub",

	// OT / ICS / SCADA specific
	"scada", "ot", "ics", "hmi", "plc", "rtu", "dcs",
	"historian", "pi", "osisoft", "osipi", "wonderware",
	"ignition", "inductive", "kepware", "opc", "opcua",
	"modbus", "dnp3", "bacnet", "profinet", "ethernetip",
	"fieldbus", "process", "automation", "control-net",
	"control-system", "control", "plant", "plant1", "plant2",
	"site", "site1", "site2", "facility", "substation",
	"substations", "rems", "ems", "bms", "pcs", "dms",
	"ami", "smart-grid", "grid", "power", "generation",
	"turbine", "compressor", "pump", "valve", "sensor",
	"data-acquisition", "rtac", "relay", "feeder",

	// Industrial network zones
	"level0", "level1", "level2", "level3", "level4", "level5",
	"ot-dmz", "ot-net", "it-ot", "purdue", "zone1", "zone2",
	"cell", "area", "enterprise", "operations",

	// Typical host naming conventions
	"server", "server1", "server2", "srv", "srv1", "srv2",
	"host", "host1", "host2", "node", "node1", "node2",
	"ws", "workstation", "pc", "desktop", "laptop",

	// Regional / geographic
	"us", "eu", "uk", "de", "fr", "asia", "apac", "emea",
	"us-east", "us-west", "east", "west", "north", "south",
	"nyc", "lon", "ams", "fra", "sin", "tok", "syd",

	// Numbered hosts
	"web1", "web2", "web3", "app1", "app2", "app3",
	"mail1", "mail2", "smtp1", "smtp2",
	"vpn1", "vpn2", "gw1", "gw2",

	// Common services
	"smtp", "http", "https", "ftp", "sftp", "ldaps",
	"radius", "snmp", "syslog", "tftp",

	// Misc
	"time", "clock", "update", "updates", "patch", "patching",
	"license", "licensing", "relay", "bridge", "hub",
	"forward", "redirect", "wpad", "autoconfiguration",
}
