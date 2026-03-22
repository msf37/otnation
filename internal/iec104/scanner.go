// Package iec104 implements IEC 60870-5-104 detection.
// Connects to port 2404, sends STARTDT-act, reads STARTDT-con and any ASDU frames.
package iec104

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var ErrNoResponse = errors.New("iec104: no response from target")

type DataObject struct {
	TypeID   uint8  `json:"type_id"`
	Address  uint32 `json:"address"`
	RawValue string `json:"raw_value"`
}

type Result struct {
	IP          string       `json:"ip"`
	Port        int          `json:"port"`
	Responded   bool         `json:"responded"`
	DeviceType  string       `json:"device_type"`
	DataObjects []DataObject `json:"data_objects"`
	RawBanner   string       `json:"raw_banner"`
}

// startdtAct is the IEC 104 STARTDT activation APDU (U-format).
var startdtAct = []byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00}

func Scan(ip string) (*Result, error) {
	addr := fmt.Sprintf("%s:2404", ip)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, ErrNoResponse
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	if _, err := conn.Write(startdtAct); err != nil {
		return nil, ErrNoResponse
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 6 {
		return nil, ErrNoResponse
	}
	buf = buf[:n]

	// STARTDT-con: 0x68 0x04 0x0B 0x00 0x00 0x00
	if buf[0] != 0x68 {
		return nil, ErrNoResponse
	}

	result := &Result{
		IP:         ip,
		Port:       2404,
		Responded:  true,
		DeviceType: "IEC 60870-5-104 RTU",
		RawBanner:  hexDump(buf),
	}

	// Check for STARTDT-con acknowledgment
	if n >= 6 && buf[0] == 0x68 && buf[1] == 0x04 && buf[2] == 0x0B {
		result.DeviceType = "IEC 60870-5-104 RTU (confirmed)"
	}

	// Read additional data (ASDUs) with short timeout
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf2 := make([]byte, 1024)
	n2, _ := conn.Read(buf2)
	if n2 > 0 {
		// Parse APDU frames looking for I-format (bit 0 of first ctrl byte = 0)
		result.DataObjects = parseASDUs(buf2[:n2])
		if len(result.DataObjects) > 0 {
			result.DeviceType = "IEC 60870-5-104 RTU (data streaming)"
		}
	}

	return result, nil
}

func parseASDUs(data []byte) []DataObject {
	var objects []DataObject
	i := 0
	for i < len(data)-5 {
		if data[i] != 0x68 {
			i++
			continue
		}
		length := int(data[i+1])
		if i+2+length > len(data) {
			break
		}
		apdu := data[i+2 : i+2+length]
		if length >= 10 && (apdu[0]&0x01) == 0 { // I-format
			typeID := apdu[4]
			// IOA is 3 bytes little-endian starting at offset 8
			if len(apdu) >= 11 {
				ioa := uint32(apdu[8]) | uint32(apdu[9])<<8 | uint32(apdu[10])<<16
				objects = append(objects, DataObject{
					TypeID:   typeID,
					Address:  ioa,
					RawValue: hexDump(apdu[11:min104(len(apdu), 15)]),
				})
			}
		}
		i += 2 + length
	}
	return objects
}

func min104(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hexDump(b []byte) string {
	if len(b) > 32 {
		b = b[:32]
	}
	var sb strings.Builder
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02X", v)
	}
	return sb.String()
}
