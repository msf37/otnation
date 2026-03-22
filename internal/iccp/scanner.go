// Package iccp detects ICCP (TASE.2 / IEC 60870-6) on port 102.
package iccp

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var ErrNoResponse = errors.New("iccp: no response from target")

type Result struct {
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Responded  bool   `json:"responded"`
	DeviceType string `json:"device_type"`
	RawBanner  string `json:"raw_banner"`
}

var cotpCR = []byte{
	0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
	0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02,
}

func Scan(ip string) (*Result, error) {
	addr := fmt.Sprintf("%s:102", ip)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, ErrNoResponse
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(cotpCR); err != nil {
		return nil, ErrNoResponse
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil, ErrNoResponse
	}
	buf = buf[:n]

	if buf[0] != 0x03 || buf[1] != 0x00 {
		return nil, ErrNoResponse
	}

	result := &Result{
		IP:        ip,
		Port:      102,
		Responded: true,
		RawBanner: hexDumpICCP(buf),
	}

	// After COTP CC, look for ACSE AARQ (0x60) vs MMS InitiateResponse (0xA1)
	// ICCP/TASE.2 uses ACSE presentation layer with AARQ tag 0x60
	for i := 4; i < len(buf)-1; i++ {
		if buf[i] == 0x60 {
			result.DeviceType = "ICCP/TASE.2 (IEC 60870-6)"
			return result, nil
		}
		if buf[i] == 0xA1 {
			// MMS — already handled by iec61850 scanner
			result.DeviceType = "COTP (MMS/IEC 61850 — not ICCP)"
			return result, nil
		}
	}

	result.DeviceType = "COTP (unknown upper layer)"
	return result, nil
}

func hexDumpICCP(b []byte) string {
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
