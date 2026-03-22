// Package otprobe probes common OT/ICS protocol ports on a target IP using
// raw TCP/UDP connections and returns whether the service responded together
// with any parsed banner data.
package otprobe

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ErrNoResponse is returned when no OT protocol responded on the target.
var ErrNoResponse = errors.New("otprobe: no OT protocols responded")

// ProbeResult holds the result for a single protocol probe.
type ProbeResult struct {
	Protocol  string            `json:"protocol"`
	Port      int               `json:"port"`
	Responded bool              `json:"responded"`
	Banner    string            `json:"banner,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

// Result aggregates all probe results for a target IP.
type Result struct {
	IP     string        `json:"ip"`
	Probes []ProbeResult `json:"probes"`
}

// Probe runs all OT protocol probes against the target IP and returns the
// aggregated results.
func Probe(ctx context.Context, ip string) (*Result, error) {
	result := &Result{IP: ip}

	probes := []ProbeResult{
		probeModbus(ctx, ip),
		probeSiemensS7(ctx, ip),
		probeBACnet(ctx, ip),
		probeEtherNetIP(ctx, ip),
		probeDNP3(ctx, ip),
	}

	result.Probes = probes

	anyResponded := false
	for _, p := range probes {
		if p.Responded {
			anyResponded = true
			break
		}
	}

	if !anyResponded {
		return result, ErrNoResponse
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Modbus TCP (port 502) — FC43 Read Device Identification
// ---------------------------------------------------------------------------

func probeModbus(ctx context.Context, ip string) ProbeResult {
	res := ProbeResult{Protocol: "Modbus TCP", Port: 502}
	request := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0xFF, 0x2B, 0x0E, 0x01, 0x00}
	raw := tcpProbe(ctx, ip, 502, request, 256)
	if raw == nil {
		return res
	}
	res.Responded = true
	res.Banner = hex.EncodeToString(raw)

	fields := make(map[string]string)
	// FC43 response: bytes [0..5] = MBAP header, [6] = unit ID, [7] = function code,
	// [8] = MEI type (0x0E), [9] = read device ID code, [10] = conformity level,
	// [11] = more follows, [12] = next object id, [13] = number of objects
	// Then objects: [tag][len][value]
	if len(raw) > 14 && raw[7] == 0x2B && raw[8] == 0x0E {
		numObjects := int(raw[13])
		pos := 14
		objectNames := map[byte]string{0x00: "VendorName", 0x01: "ProductCode", 0x02: "MajorMinorRevision"}
		for i := 0; i < numObjects && pos+2 < len(raw); i++ {
			objID := raw[pos]
			objLen := int(raw[pos+1])
			pos += 2
			if pos+objLen > len(raw) {
				break
			}
			val := string(raw[pos : pos+objLen])
			if name, ok := objectNames[objID]; ok {
				fields[name] = val
			}
			pos += objLen
		}
	}
	if len(fields) > 0 {
		res.Fields = fields
	}
	return res
}

// ---------------------------------------------------------------------------
// Siemens S7 (port 102) — COTP CR + S7 Setup
// ---------------------------------------------------------------------------

func probeSiemensS7(ctx context.Context, ip string) ProbeResult {
	res := ProbeResult{Protocol: "Siemens S7", Port: 102}
	cotpCR := []byte{
		0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00,
		0x00, 0x01, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02,
		0x01, 0x00, 0xC2, 0x02, 0x01, 0x02,
	}
	raw := tcpProbe(ctx, ip, 102, cotpCR, 256)
	if raw == nil {
		return res
	}
	// Check for COTP CC (Connection Confirm): tag 0xD0
	if len(raw) < 5 || raw[5] != 0xD0 {
		return res
	}

	// Send S7 Setup Communication
	conn, err := dialTCPWithContext(ctx, ip, 102)
	if err != nil {
		res.Responded = true
		res.Banner = hex.EncodeToString(raw)
		return res
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	conn.Write(cotpCR)                                 //nolint:errcheck
	buf1 := make([]byte, 256)
	conn.Read(buf1) //nolint:errcheck

	s7Setup := []byte{
		0x03, 0x00, 0x00, 0x19, 0x02, 0xF0, 0x80, 0x32,
		0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x08, 0x00,
		0x00, 0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0,
	}
	conn.Write(s7Setup) //nolint:errcheck

	buf2 := make([]byte, 512)
	n, _ := conn.Read(buf2)

	res.Responded = true
	res.Banner = hex.EncodeToString(raw)
	if n > 0 {
		res.Banner += "|" + hex.EncodeToString(buf2[:n])
	}

	fields := map[string]string{"type": "Siemens S7 PLC"}
	res.Fields = fields
	return res
}

// ---------------------------------------------------------------------------
// BACnet UDP (port 47808 / 0xBAC0) — WhoIs unicast
// ---------------------------------------------------------------------------

func probeBACnet(ctx context.Context, ip string) ProbeResult {
	res := ProbeResult{Protocol: "BACnet", Port: 47808}
	request := []byte{0x81, 0x0B, 0x00, 0x08, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08}
	raw := udpProbe(ctx, ip, 47808, request, 256)
	if raw == nil {
		return res
	}
	res.Responded = true
	res.Banner = hex.EncodeToString(raw)

	fields := make(map[string]string)
	// BACnet BVLL header: [0]=0x81 type, [1]=function, [2-3]=length
	// NPDU: [4]=0x01 version, [5]=control
	// APDU starts at [6]: [6]=PDU type/flags, [7]=service
	if len(raw) >= 4 && raw[0] == 0x81 {
		bvllFunc := raw[1]
		switch bvllFunc {
		case 0x0B:
			fields["bvll_function"] = "Original-Unicast-NPDU"
		case 0x0A:
			fields["bvll_function"] = "Original-Broadcast-NPDU"
		case 0x04:
			fields["bvll_function"] = "Forwarded-NPDU"
		}
	}
	if len(fields) > 0 {
		res.Fields = fields
	}
	return res
}

// ---------------------------------------------------------------------------
// EtherNet/IP (port 44818) — ListIdentity
// ---------------------------------------------------------------------------

func probeEtherNetIP(ctx context.Context, ip string) ProbeResult {
	res := ProbeResult{Protocol: "EtherNet/IP", Port: 44818}
	request := []byte{
		0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	raw := tcpProbe(ctx, ip, 44818, request, 512)
	if raw == nil {
		return res
	}
	res.Responded = true
	res.Banner = hex.EncodeToString(raw)

	fields := make(map[string]string)
	// EtherNet/IP encapsulation header is 24 bytes:
	// [0-1] command, [2-3] length, [4-7] session handle, [8-11] status,
	// [12-19] sender context, [20-23] options
	// ListIdentity response command = 0x0063
	if len(raw) >= 4 {
		cmd := uint16(raw[0]) | (uint16(raw[1]) << 8)
		if cmd == 0x0063 {
			fields["command"] = "ListIdentity"
		}
	}
	// Try to extract product name from item data (heuristic: look for printable ASCII run)
	if len(raw) > 24 {
		data := raw[24:]
		for i := 0; i+1 < len(data); i++ {
			// Item type 0x000C = CIP Identity
			if data[i] == 0x0C && i+1 < len(data) && data[i+1] == 0x00 {
				if i+4 < len(data) {
					itemLen := int(data[i+2]) | (int(data[i+3]) << 8)
					if i+4+itemLen <= len(data) {
						fields["identity_item_len"] = fmt.Sprintf("%d", itemLen)
						// Product name starts after fixed CIP identity fields (28 bytes offset)
						offset := i + 4 + 28
						if offset < len(data) {
							nameLen := int(data[offset])
							offset++
							if offset+nameLen <= len(data) {
								fields["product_name"] = string(data[offset : offset+nameLen])
							}
						}
					}
				}
				break
			}
		}
	}
	if len(fields) > 0 {
		res.Fields = fields
	}
	return res
}

// ---------------------------------------------------------------------------
// DNP3 (port 20000) — Link Layer Test frame
// ---------------------------------------------------------------------------

// dnp3CRC computes the DNP3 CRC-16 for a byte slice.
func dnp3CRC(data []byte) uint16 {
	crc := uint16(0)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

func probeDNP3(ctx context.Context, ip string) ProbeResult {
	res := ProbeResult{Protocol: "DNP3", Port: 20000}

	// Link layer frame with CRC appended.
	// Header bytes (8 bytes): start (0x0564), len, ctrl, dst lo, dst hi, src lo, src hi
	header := []byte{0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04}
	crc := dnp3CRC(header)
	frame := append(header, byte(crc&0xFF), byte(crc>>8))

	raw := tcpProbe(ctx, ip, 20000, frame, 256)
	if raw == nil {
		return res
	}
	res.Responded = true
	res.Banner = hex.EncodeToString(raw)

	fields := make(map[string]string)
	if len(raw) >= 2 && raw[0] == 0x05 && raw[1] == 0x64 {
		fields["type"] = "DNP3 Link Layer"
		if len(raw) >= 4 {
			ctrl := raw[3]
			fcv := (ctrl >> 4) & 0x01
			fc := ctrl & 0x0F
			fields["frame_control"] = fmt.Sprintf("0x%02X (FCV=%d FC=%d)", ctrl, fcv, fc)
		}
	}
	if len(fields) > 0 {
		res.Fields = fields
	}
	return res
}

// ---------------------------------------------------------------------------
// TCP/UDP helpers
// ---------------------------------------------------------------------------

func tcpProbe(ctx context.Context, ip string, port int, request []byte, readLen int) []byte {
	conn, err := dialTCPWithContext(ctx, ip, port)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	if _, err := conn.Write(request); err != nil {
		return nil
	}

	buf := make([]byte, readLen)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}
	return buf[:n]
}

func udpProbe(ctx context.Context, ip string, port int, request []byte, readLen int) []byte {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("udp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline) //nolint:errcheck

	if _, err := conn.Write(request); err != nil {
		return nil
	}

	buf := make([]byte, readLen)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}
	return buf[:n]
}

func dialTCPWithContext(ctx context.Context, ip string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: 3 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

// joinFields formats a map as "key=val key=val".
func joinFields(fields map[string]string) string {
	parts := make([]string, 0, len(fields))
	for k, v := range fields {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

var _ = joinFields // suppress unused warning
