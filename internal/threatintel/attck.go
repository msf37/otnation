// Package threatintel provides MITRE ATT&CK for ICS TTP mapping and default credential testing.
package threatintel

// TTP represents a MITRE ATT&CK for ICS technique.
type TTP struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	Tactic        string `json:"tactic"`
}

// protocolTTPs maps protocol/category strings to applicable ATT&CK for ICS TTPs.
var protocolTTPs = map[string][]TTP{
	"modbus": {
		{TechniqueID: "T0846", TechniqueName: "Remote System Discovery", Tactic: "Discovery"},
		{TechniqueID: "T0855", TechniqueName: "Unauthorized Command Message", Tactic: "Impair Process Control"},
		{TechniqueID: "T0869", TechniqueName: "Standard Application Layer Protocol", Tactic: "Command and Control"},
	},
	"dnp3": {
		{TechniqueID: "T0856", TechniqueName: "Spoof Reporting Message", Tactic: "Impair Process Control"},
		{TechniqueID: "T0855", TechniqueName: "Unauthorized Command Message", Tactic: "Impair Process Control"},
		{TechniqueID: "T0869", TechniqueName: "Standard Application Layer Protocol", Tactic: "Command and Control"},
	},
	"iec104": {
		{TechniqueID: "T0869", TechniqueName: "Standard Application Layer Protocol", Tactic: "Command and Control"},
		{TechniqueID: "T0883", TechniqueName: "Internet Accessible Device", Tactic: "Initial Access"},
		{TechniqueID: "T0855", TechniqueName: "Unauthorized Command Message", Tactic: "Impair Process Control"},
		{TechniqueID: "T0856", TechniqueName: "Spoof Reporting Message", Tactic: "Impair Process Control"},
	},
	"iec61850": {
		{TechniqueID: "T0817", TechniqueName: "Drive-by Compromise", Tactic: "Initial Access"},
		{TechniqueID: "T0853", TechniqueName: "Scripting", Tactic: "Execution"},
		{TechniqueID: "T0855", TechniqueName: "Unauthorized Command Message", Tactic: "Impair Process Control"},
	},
	"enip": {
		{TechniqueID: "T0840", TechniqueName: "Network Connection Enumeration", Tactic: "Discovery"},
		{TechniqueID: "T0843", TechniqueName: "Program Download", Tactic: "Impair Process Control"},
		{TechniqueID: "T0845", TechniqueName: "Program Upload", Tactic: "Collection"},
	},
	"s7": {
		{TechniqueID: "T0845", TechniqueName: "Program Upload", Tactic: "Collection"},
		{TechniqueID: "T0843", TechniqueName: "Program Download", Tactic: "Impair Process Control"},
		{TechniqueID: "T0866", TechniqueName: "Exploitation of Remote Services", Tactic: "Lateral Movement"},
	},
	"opcua": {
		{TechniqueID: "T0884", TechniqueName: "Connection Proxy", Tactic: "Command and Control"},
		{TechniqueID: "T0840", TechniqueName: "Network Connection Enumeration", Tactic: "Discovery"},
		{TechniqueID: "T0869", TechniqueName: "Standard Application Layer Protocol", Tactic: "Command and Control"},
	},
	"profinet": {
		{TechniqueID: "T0846", TechniqueName: "Remote System Discovery", Tactic: "Discovery"},
		{TechniqueID: "T0840", TechniqueName: "Network Connection Enumeration", Tactic: "Discovery"},
	},
	"iccp": {
		{TechniqueID: "T0869", TechniqueName: "Standard Application Layer Protocol", Tactic: "Command and Control"},
		{TechniqueID: "T0883", TechniqueName: "Internet Accessible Device", Tactic: "Initial Access"},
		{TechniqueID: "T0856", TechniqueName: "Spoof Reporting Message", Tactic: "Impair Process Control"},
	},
	"hmi": {
		{TechniqueID: "T0883", TechniqueName: "Internet Accessible Device", Tactic: "Initial Access"},
		{TechniqueID: "T0817", TechniqueName: "Drive-by Compromise", Tactic: "Initial Access"},
		{TechniqueID: "T0866", TechniqueName: "Exploitation of Remote Services", Tactic: "Lateral Movement"},
	},
	"default_creds": {
		{TechniqueID: "T0859", TechniqueName: "Valid Accounts", Tactic: "Lateral Movement"},
		{TechniqueID: "T0866", TechniqueName: "Exploitation of Remote Services", Tactic: "Lateral Movement"},
	},
	"historian": {
		{TechniqueID: "T0882", TechniqueName: "Theft of Operational Information", Tactic: "Collection"},
		{TechniqueID: "T0840", TechniqueName: "Network Connection Enumeration", Tactic: "Discovery"},
	},
}

// LookupTTPs returns ATT&CK for ICS TTPs for the given protocol and/or category.
// protocol and category are matched case-insensitively against the map keys.
func LookupTTPs(protocol, category string) []TTP {
	seen := map[string]bool{}
	var result []TTP
	for _, key := range []string{protocol, category} {
		if ttps, ok := protocolTTPs[key]; ok {
			for _, t := range ttps {
				if !seen[t.TechniqueID] {
					seen[t.TechniqueID] = true
					result = append(result, t)
				}
			}
		}
	}
	// Generic internet-accessible finding
	if protocol == "iec104" || protocol == "iec61850" || protocol == "iccp" {
		t := TTP{TechniqueID: "T0883", TechniqueName: "Internet Accessible Device", Tactic: "Initial Access"}
		if !seen[t.TechniqueID] {
			result = append(result, t)
		}
	}
	return result
}
