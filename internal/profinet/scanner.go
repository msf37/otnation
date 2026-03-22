// Package profinet detects Profinet DCP devices via UDP port 34964.
package profinet

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var ErrNoResponse = errors.New("profinet: no response")

type Result struct {
	IP          string `json:"ip"`
	Responded   bool   `json:"responded"`
	StationName string `json:"station_name,omitempty"`
	VendorID    string `json:"vendor_id,omitempty"`
	RawBanner   string `json:"raw_banner"`
}

// DCP Identify request targeting a specific IP (unicast)
// Frame ID 0xFEFE, ServiceID=5 (Identify), ServiceType=0 (Request)
var dcpIdentify = []byte{
	0xFE, 0xFE,             // FrameID
	0x05,                   // ServiceID: Identify
	0x00,                   // ServiceType: Request
	0x00, 0x00, 0x00, 0x01, // XID
	0x00, 0x00,             // ResponseDelay
	0x00, 0x04,             // DCPDataLength = 4
	0xFF, 0xFF,             // Option=0xFF (All), SubOption=0xFF (All)
	0x00, 0x00,             // DCPBlockLength = 0
}

func Scan(ip string) (*Result, error) {
	addr := fmt.Sprintf("%s:34964", ip)
	conn, err := net.DialTimeout("udp", addr, 4*time.Second)
	if err != nil {
		return nil, ErrNoResponse
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(dcpIdentify); err != nil {
		return nil, ErrNoResponse
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil, ErrNoResponse
	}
	buf = buf[:n]

	result := &Result{
		IP:        ip,
		Responded: true,
		RawBanner: hexDumpPN(buf),
	}

	// Parse DCP response blocks for station name (option 2, suboption 2)
	// and vendor ID (option 2, suboption 1)
	if n >= 12 {
		offset := 12 // skip header
		for offset+4 <= n {
			opt := buf[offset]
			sub := buf[offset+1]
			blockLen := int(buf[offset+2])<<8 | int(buf[offset+3])
			if offset+4+blockLen > n {
				break
			}
			blockData := buf[offset+4 : offset+4+blockLen]
			switch {
			case opt == 0x02 && sub == 0x02 && blockLen > 2:
				// Station name (skip 2-byte BlockInfo)
				result.StationName = sanitize(blockData[2:])
			case opt == 0x02 && sub == 0x01 && blockLen >= 4:
				result.VendorID = fmt.Sprintf("0x%02X%02X", blockData[2], blockData[3])
			}
			offset += 4 + blockLen
			if blockLen%2 != 0 {
				offset++ // padding
			}
		}
	}

	return result, nil
}

func sanitize(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c <= 0x7E {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func hexDumpPN(b []byte) string {
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
