// Package iec61850 implements a minimal IEC 61850 MMS scanner.
// It connects to port 102, sends a COTP Connection Request, then an MMS
// Initiate-Request PDU, and parses the response to extract device info.
package iec61850

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrNoResponse is returned when the target does not respond within the timeout.
var ErrNoResponse = errors.New("iec61850: no response from target")

// Result holds the outcome of an IEC 61850 scan.
type Result struct {
	IP             string   `json:"ip"`
	Port           int      `json:"port"`
	Responded      bool     `json:"responded"`
	DeviceType     string   `json:"device_type"`
	LogicalDevices []string `json:"logical_devices"`
	RawBanner      string   `json:"raw_banner"`
}

// cotpCR is a standard COTP Connection Request (CR) TPDU used by both S7 and MMS.
var cotpCR = []byte{
	0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
	0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02,
}

// mmsInitiateRequest is a minimal MMS Initiate-Request PDU.
var mmsInitiateRequest = []byte{
	0x03, 0x00, 0x00, 0x21, 0x02, 0xF0, 0x80, 0x01, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// Scan connects to ip:102, performs the COTP+MMS handshake and returns a Result.
func Scan(ip string) (*Result, error) {
	port := 102
	addr := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, ErrNoResponse
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send COTP CR.
	if _, err := conn.Write(cotpCR); err != nil {
		return nil, ErrNoResponse
	}

	// Read COTP response (at least 4 bytes).
	cotpResp := make([]byte, 256)
	n, err := conn.Read(cotpResp)
	if err != nil || n < 4 {
		return nil, ErrNoResponse
	}
	cotpResp = cotpResp[:n]

	// COTP CC (Connection Confirm) has code 0xD0 at byte 5 (0-indexed byte 4 of TPDU).
	// A valid COTP response starts with 0x03 0x00.
	if cotpResp[0] != 0x03 || cotpResp[1] != 0x00 {
		return nil, ErrNoResponse
	}

	result := &Result{
		IP:        ip,
		Port:      port,
		Responded: true,
	}

	// Check if it's S7 (COTP CC followed by S7 comm params at byte 5 = 0xD0).
	// byte index 4 of the TPDU (offset 4 after TPKT 4-byte header) is COTP code.
	if len(cotpResp) > 5 && cotpResp[5] == 0xD0 {
		// Looks like COTP CC — could be S7 or MMS. Send MMS Initiate.
	} else if len(cotpResp) > 4 {
		// Might already contain S7 data, check for S7 comm signature.
		if containsBytes(cotpResp, []byte{0x32, 0x03}) {
			result.DeviceType = "S7/Siemens PLC"
			result.RawBanner = hexDump(cotpResp)
			return result, nil
		}
	}

	// Send MMS Initiate-Request.
	if _, err := conn.Write(mmsInitiateRequest); err != nil {
		result.DeviceType = "COTP (unknown)"
		result.RawBanner = hexDump(cotpResp)
		return result, nil
	}

	// Read MMS response.
	mmsResp := make([]byte, 1024)
	n, err = conn.Read(mmsResp)
	if err != nil || n < 4 {
		result.DeviceType = "COTP (no MMS response)"
		result.RawBanner = hexDump(cotpResp)
		return result, nil
	}
	mmsResp = mmsResp[:n]

	result.RawBanner = hexDump(mmsResp)

	// Check for valid MMS Initiate-Response: starts with 0x03 0x00 and contains 0xA1 tag.
	if mmsResp[0] == 0x03 && mmsResp[1] == 0x00 && containsByte(mmsResp, 0xA1) {
		result.DeviceType = "IEC 61850 MMS"
		result.LogicalDevices = extractPrintableStrings(mmsResp, 4, 32)
	} else if containsBytes(mmsResp, []byte{0x32, 0x03}) {
		result.DeviceType = "S7/Siemens PLC"
	} else {
		result.DeviceType = "COTP (unknown protocol)"
	}

	return result, nil
}

// containsByte returns true if b is in data.
func containsByte(data []byte, b byte) bool {
	for _, v := range data {
		if v == b {
			return true
		}
	}
	return false
}

// containsBytes returns true if needle appears anywhere in haystack.
func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// extractPrintableStrings scans data for printable ASCII runs of length [minLen, maxLen].
func extractPrintableStrings(data []byte, minLen, maxLen int) []string {
	var result []string
	seen := map[string]bool{}
	cur := []byte{}

	flush := func() {
		if len(cur) >= minLen && len(cur) <= maxLen {
			s := string(cur)
			if !seen[s] {
				seen[s] = true
				result = append(result, s)
			}
		}
		cur = cur[:0]
	}

	for _, b := range data {
		if b >= 0x20 && b <= 0x7E {
			cur = append(cur, b)
			if len(cur) > maxLen {
				cur = cur[:0] // reset on overlong
			}
		} else {
			flush()
		}
	}
	flush()
	return result
}

// hexDump returns the first 64 bytes as a hex string.
func hexDump(b []byte) string {
	if len(b) > 64 {
		b = b[:64]
	}
	out := ""
	for i, v := range b {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%02X", v)
	}
	return out
}
