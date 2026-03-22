// Package banner provides banner-based service classification for SCADA platforms.
package banner

import (
	"strings"
)

// Classification holds the result of classifying a service by port and banner.
type Classification struct {
	ServiceName string
	Category    string
	Vendor      string
	Confidence  float64
}

// Classify determines the service type from the port number and raw banner text.
// Port-based rules are applied first; banner text matching may increase confidence.
func Classify(port int, rawBanner string) Classification {
	// Start with port-based classification.
	c := classifyByPort(port)

	// Apply banner text matching and potentially override / increase confidence.
	if bc, ok := classifyByBanner(rawBanner); ok {
		// If we already had a match from port rules, only override if banner is more confident.
		if c.ServiceName == "Unknown" || bc.Confidence > c.Confidence {
			c = bc
		}
	}

	return c
}

// classifyByPort returns a Classification based solely on the port number.
func classifyByPort(port int) Classification {
	switch port {
	case 502:
		return Classification{"Modbus", "industrial_protocol", "Modbus", 0.9}
	case 102:
		return Classification{"ISOTSAP/S7", "industrial_protocol", "Siemens", 0.9}
	case 20000:
		return Classification{"DNP3", "industrial_protocol", "DNP3", 0.9}
	case 44818:
		return Classification{"EtherNet/IP", "industrial_protocol", "Rockwell", 0.9}
	case 47808:
		return Classification{"BACnet", "industrial_protocol", "BACnet", 0.9}
	case 4840:
		return Classification{"OPC-UA", "industrial_protocol", "OPC", 0.85}
	case 1911:
		return Classification{"Niagara/Fox", "industrial_protocol", "Tridium", 0.85}
	case 9600:
		return Classification{"OMRON FINS", "industrial_protocol", "OMRON", 0.85}
	case 2404:
		return Classification{"IEC-104", "industrial_protocol", "IEC", 0.9}
	case 4000:
		return Classification{"Emerson DeltaV", "industrial_protocol", "Emerson", 0.8}
	case 20547:
		return Classification{"ProConOs", "industrial_protocol", "ProConOs", 0.8}
	case 38400:
		return Classification{"MELSEC", "industrial_protocol", "Mitsubishi", 0.8}
	case 22:
		return Classification{"SSH", "remote_access", "", 0.95}
	case 3389:
		return Classification{"RDP", "remote_access", "Microsoft", 0.95}
	case 5900:
		return Classification{"VNC", "remote_access", "", 0.9}
	case 23:
		return Classification{"Telnet", "remote_access", "", 0.95}
	case 80, 8080:
		return Classification{"HTTP", "web_interface", "", 0.8}
	case 443, 8443:
		return Classification{"HTTPS", "web_interface", "", 0.9}
	}
	return Classification{ServiceName: "Unknown", Category: "unknown", Confidence: 0.1}
}

// classifyByBanner attempts to identify a service from the raw banner text.
// Returns (Classification, true) on a match, or (zero, false) if no rule fires.
func classifyByBanner(rawBanner string) (Classification, bool) {
	if rawBanner == "" {
		return Classification{}, false
	}
	lower := strings.ToLower(rawBanner)

	switch {
	case strings.Contains(lower, "modbus"):
		return Classification{"Modbus", "industrial_protocol", "Modbus", 0.95}, true
	case strings.Contains(lower, "siemens") || strings.Contains(lower, "s7-"):
		return Classification{"Siemens S7", "industrial_protocol", "Siemens", 0.95}, true
	case strings.Contains(lower, "schneider") || strings.Contains(lower, "unity"):
		return Classification{"Schneider", "industrial_protocol", "Schneider Electric", 0.9}, true
	case strings.Contains(lower, "rockwell") || strings.Contains(lower, "allen-brad") || strings.Contains(lower, "controllogix"):
		return Classification{"EtherNet/IP", "industrial_protocol", "Rockwell", 0.95}, true
	case strings.Contains(lower, "bacnet"):
		return Classification{"BACnet", "industrial_protocol", "BACnet", 0.95}, true
	case strings.Contains(lower, "niagara") || strings.Contains(lower, "jace"):
		return Classification{"Niagara", "industrial_protocol", "Tridium", 0.9}, true
	case strings.Contains(lower, "ssh-"):
		return Classification{"SSH", "remote_access", "", 0.95}, true
	case strings.Contains(lower, "vnc"):
		return Classification{"VNC", "remote_access", "", 0.92}, true
	case strings.Contains(lower, "mysql"):
		return Classification{"MySQL", "database", "MySQL", 0.95}, true
	case strings.Contains(lower, "postgresql") || strings.Contains(lower, "postgres"):
		return Classification{"PostgreSQL", "database", "PostgreSQL", 0.95}, true
	}

	return Classification{}, false
}
