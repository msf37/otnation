// Package dnp3deep performs deep DNP3 scanning by sending Read Class 0.
package dnp3deep

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var ErrNoResponse = errors.New("dnp3deep: no response")

type DataPoint struct {
	Group uint8  `json:"group"`
	Var   uint8  `json:"var"`
	Index uint16 `json:"index"`
	Value string `json:"value"`
}

type Result struct {
	IP         string      `json:"ip"`
	Port       int         `json:"port"`
	Responded  bool        `json:"responded"`
	DataPoints []DataPoint `json:"data_points"`
	RawBanner  string      `json:"raw_banner"`
}

func Scan(ip string) (*Result, error) {
	addr := fmt.Sprintf("%s:20000", ip)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, ErrNoResponse
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	// DNP3 Link Layer Reset frame
	reset := buildDNP3LinkReset()
	if _, err := conn.Write(reset); err != nil {
		return nil, ErrNoResponse
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil, ErrNoResponse
	}

	result := &Result{
		IP:        ip,
		Port:      20000,
		Responded: true,
		RawBanner: hexDumpDNP3(buf[:n]),
	}

	// Send Read Class 0 (group 60 var 1 — all static data)
	readClass0 := buildDNP3ReadClass0()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(readClass0); err != nil {
		return result, nil
	}

	buf2 := make([]byte, 2048)
	n2, _ := conn.Read(buf2)
	if n2 > 10 {
		result.DataPoints = parseDNP3Response(buf2[:n2])
	}

	return result, nil
}

// buildDNP3LinkReset builds a DNP3 link layer Reset Link States frame.
func buildDNP3LinkReset() []byte {
	// Frame: start(2) + len(1) + ctrl(1) + dst(2) + src(2) + CRC(2)
	frame := []byte{0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0xE8, 0x03}
	crc := dnp3CRC(frame)
	return append(frame, byte(crc), byte(crc>>8))
}

// buildDNP3ReadClass0 builds a DNP3 Read Class 0 request (application layer).
func buildDNP3ReadClass0() []byte {
	// Application layer: FIR=1, FIN=1, CON=0, UNS=0, SEQ=0, FC=1 (READ)
	// Object group 60 (Class), var 1 (Class 0)
	appLayer := []byte{0xC0, 0x01, 0x3C, 0x01, 0x06}
	// Transport layer header: FIR=1, FIN=1, seq=0 → 0xC0
	transportHdr := byte(0xC0)
	// Link layer: data frame, src=1000, dst=1
	payload := append([]byte{transportHdr}, appLayer...)
	length := byte(5 + len(payload))
	frame := []byte{0x05, 0x64, length, 0x44, 0x01, 0x00, 0xE8, 0x03}
	headerCRC := dnp3CRC(frame)
	frame = append(frame, byte(headerCRC), byte(headerCRC>>8))
	// Data chunk with CRC every 16 bytes
	chunk := payload
	if len(chunk) <= 16 {
		chunkCRC := dnp3CRC(chunk)
		frame = append(frame, chunk...)
		frame = append(frame, byte(chunkCRC), byte(chunkCRC>>8))
	}
	return frame
}

func parseDNP3Response(data []byte) []DataPoint {
	var points []DataPoint
	// Look for DNP3 start bytes 0x05 0x64
	for i := 0; i < len(data)-10; i++ {
		if data[i] == 0x05 && data[i+1] == 0x64 {
			// Found a frame, extract group/var if application data present
			if i+10 < len(data) {
				// Skip header (10 bytes) + transport (1 byte) + app header (2 bytes)
				offset := i + 13
				if offset+4 < len(data) {
					grp := data[offset]
					vr := data[offset+1]
					points = append(points, DataPoint{
						Group: grp,
						Var:   vr,
						Index: 0,
						Value: hexDumpDNP3(data[offset:minDNP3(len(data), offset+8)]),
					})
				}
			}
			break
		}
	}
	return points
}

func dnp3CRC(data []byte) uint16 {
	const poly = uint16(0xA6BC)
	crc := uint16(0x0000)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&0x0001 != 0 {
				crc = (crc >> 1) ^ poly
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

func minDNP3(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hexDumpDNP3(b []byte) string {
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
