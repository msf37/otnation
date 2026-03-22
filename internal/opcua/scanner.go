// Package opcua performs OPC-UA endpoint enumeration on port 4840.
package opcua

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var ErrNoResponse = errors.New("opcua: no response from target")

type Endpoint struct {
	URL               string `json:"url"`
	SecurityMode      string `json:"security_mode"`
	SecurityPolicyURI string `json:"security_policy_uri"`
}

type Result struct {
	IP        string     `json:"ip"`
	Port      int        `json:"port"`
	Responded bool       `json:"responded"`
	ServerURI string     `json:"server_uri,omitempty"`
	Endpoints []Endpoint `json:"endpoints"`
	RawBanner string     `json:"raw_banner"`
}

func Scan(ip string) (*Result, error) {
	addr := fmt.Sprintf("%s:4840", ip)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, ErrNoResponse
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	endpointURL := fmt.Sprintf("opc.tcp://%s:4840", ip)

	// Send Hello message
	helloMsg := buildOPCUAHello(endpointURL)
	if _, err := conn.Write(helloMsg); err != nil {
		return nil, ErrNoResponse
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return nil, ErrNoResponse
	}

	result := &Result{
		IP:        ip,
		Port:      4840,
		Responded: true,
		RawBanner: hexDumpUA(buf[:n]),
	}

	// Check for ACK response (msg type "ACK")
	if n >= 4 && string(buf[0:3]) == "ACK" {
		result.ServerURI = "OPC-UA Server (ACK received)"
	} else if n >= 4 && string(buf[0:3]) == "ERR" {
		result.ServerURI = "OPC-UA Server (Error response)"
		return result, nil
	} else {
		return result, nil
	}

	// Send OpenSecureChannel (None security)
	osc := buildOpenSecureChannel()
	if _, err := conn.Write(osc); err != nil {
		return result, nil
	}
	buf2 := make([]byte, 4096)
	n2, err := conn.Read(buf2)
	if err != nil || n2 < 32 {
		return result, nil
	}

	// Extract endpoint URLs from the response by scanning for opc.tcp:// strings
	result.Endpoints = extractEndpoints(buf2[:n2])

	return result, nil
}

func buildOPCUAHello(endpointURL string) []byte {
	urlBytes := []byte(endpointURL)
	urlLen := len(urlBytes)
	// Hello: type(3) + 'F'(1) + size(4) + version(4) + receiveBufferSize(4) + sendBufferSize(4) + maxMessageSize(4) + maxChunkCount(4) + endpointURLLength(4) + endpointURL
	size := 8 + 5*4 + 4 + urlLen
	msg := make([]byte, size)
	copy(msg[0:], "HELF")
	binary.LittleEndian.PutUint32(msg[4:], uint32(size))
	binary.LittleEndian.PutUint32(msg[8:], 0)      // version
	binary.LittleEndian.PutUint32(msg[12:], 65536) // receiveBufferSize
	binary.LittleEndian.PutUint32(msg[16:], 65536) // sendBufferSize
	binary.LittleEndian.PutUint32(msg[20:], 0)     // maxMessageSize
	binary.LittleEndian.PutUint32(msg[24:], 0)     // maxChunkCount
	binary.LittleEndian.PutUint32(msg[28:], uint32(urlLen))
	copy(msg[32:], urlBytes)
	return msg
}

func buildOpenSecureChannel() []byte {
	// Minimal OpenSecureChannel request with SecurityMode=None
	payload := []byte{
		// MessageHeader: OPNF + size placeholder
		0x4F, 0x50, 0x4E, 0x46, // "OPNF"
		0x00, 0x00, 0x00, 0x00, // size (fill below)
		// SecureChannelId
		0x00, 0x00, 0x00, 0x00,
		// SecurityPolicyURI: "http://opcfoundation.org/UA/SecurityPolicy#None"
		0x2E, 0x00, 0x00, 0x00,
	}
	secPol := []byte("http://opcfoundation.org/UA/SecurityPolicy#None")
	payload = append(payload, secPol...)
	// SenderCertificate and ReceiverCertificateThumbprint (null)
	payload = append(payload, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
	// SequenceHeader
	payload = append(payload, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00)
	// RequestHeader + OpenSecureChannelRequest body (minimal)
	payload = append(payload,
		0x00, 0x00, // NodeId (numeric, id=446 = OpenSecureChannelRequest)
		0xBE, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AuthenticationToken (null)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
		0x01, 0x00, 0x00, 0x00, // RequestHandle
		0x00, 0x00, 0x00, 0x00, // ReturnDiagnostics
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AuditEntryId (null)
		0x00, 0x00, 0x00, 0x00, // TimeoutHint
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AdditionalHeader (null)
		// SecurityTokenRequestType: 0=Issue
		0x00, 0x00, 0x00, 0x00,
		// MessageSecurityMode: 1=None
		0x01, 0x00, 0x00, 0x00,
		// ClientNonce (null)
		0xFF, 0xFF, 0xFF, 0xFF,
		// RequestedLifetime: 3600000ms
		0x80, 0xEE, 0x36, 0x00,
	)
	binary.LittleEndian.PutUint32(payload[4:], uint32(len(payload)))
	return payload
}

func extractEndpoints(data []byte) []Endpoint {
	var endpoints []Endpoint
	seen := map[string]bool{}
	s := string(data)
	for {
		idx := strings.Index(s, "opc.tcp://")
		if idx < 0 {
			break
		}
		end := idx + 10
		for end < len(s) && s[end] != 0x00 && s[end] >= 0x20 && s[end] <= 0x7E {
			end++
		}
		url := strings.TrimSpace(s[idx:end])
		if len(url) > 10 && len(url) < 200 && !seen[url] {
			seen[url] = true
			endpoints = append(endpoints, Endpoint{
				URL:               url,
				SecurityMode:      "None",
				SecurityPolicyURI: "http://opcfoundation.org/UA/SecurityPolicy#None",
			})
		}
		s = s[end:]
	}
	return endpoints
}

func hexDumpUA(b []byte) string {
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
