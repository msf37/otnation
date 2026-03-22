// Package enipdeep performs EtherNet/IP CIP deep enumeration.
package enipdeep

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var ErrNoResponse = errors.New("enipdeep: no response")

type Tag struct {
	Name       string `json:"name"`
	TypeCode   uint16 `json:"type_code"`
	InstanceID uint32 `json:"instance_id"`
}

type Result struct {
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Responded   bool   `json:"responded"`
	ProductName string `json:"product_name,omitempty"`
	VendorID    uint16 `json:"vendor_id,omitempty"`
	DeviceType  uint16 `json:"device_type,omitempty"`
	Tags        []Tag  `json:"tags"`
	RawBanner   string `json:"raw_banner"`
}

func Scan(ip string) (*Result, error) {
	addr := fmt.Sprintf("%s:44818", ip)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, ErrNoResponse
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	// Step 1: ListIdentity (command 0x0063)
	listID := buildEIPCommand(0x0063, nil)
	if _, err := conn.Write(listID); err != nil {
		return nil, ErrNoResponse
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 24 {
		return nil, ErrNoResponse
	}

	result := &Result{
		IP:        ip,
		Port:      44818,
		Responded: true,
		RawBanner: hexDumpEIP(buf[:n]),
	}

	// Parse ListIdentity response for product name
	result.ProductName, result.VendorID, result.DeviceType = parseListIdentity(buf[:n])

	// Step 2: Register Session (command 0x0065)
	regSession := buildRegisterSession()
	if _, err := conn.Write(regSession); err != nil {
		return result, nil
	}
	buf2 := make([]byte, 1024)
	n2, err := conn.Read(buf2)
	if err != nil || n2 < 28 {
		return result, nil
	}
	sessionHandle := binary.LittleEndian.Uint32(buf2[4:8])

	// Step 3: Send UnconnectedSend to Get_Attribute_All on Identity object (class 0x01, instance 0x01)
	getAttr := buildGetAttributeAll(sessionHandle)
	if _, err := conn.Write(getAttr); err != nil {
		return result, nil
	}
	buf3 := make([]byte, 2048)
	n3, _ := conn.Read(buf3)
	if n3 > 44 {
		tags := extractCIPStrings(buf3[:n3])
		for _, t := range tags {
			result.Tags = append(result.Tags, Tag{Name: t, TypeCode: 0, InstanceID: 0})
		}
	}

	return result, nil
}

func buildEIPCommand(command uint16, data []byte) []byte {
	h := make([]byte, 24)
	binary.LittleEndian.PutUint16(h[0:], command)
	binary.LittleEndian.PutUint16(h[2:], uint16(len(data)))
	return append(h, data...)
}

func buildRegisterSession() []byte {
	data := []byte{0x01, 0x00, 0x00, 0x00} // version=1, options=0
	return buildEIPCommand(0x0065, data)
}

func buildGetAttributeAll(sessionHandle uint32) []byte {
	// CIP path: class 0x01 (Identity), instance 0x01
	cipPath := []byte{0x20, 0x01, 0x24, 0x01} // logical segment class/instance
	// CIP service 0x01 (Get_Attribute_All)
	cipReq := append([]byte{0x01, byte(len(cipPath) / 2)}, cipPath...)
	// SendRRData (0x0065) encapsulation
	encapData := append([]byte{
		0x00, 0x00, 0x00, 0x00, // interface handle
		0x00, 0x00,             // timeout
		0x02, 0x00,             // item count = 2
		0x00, 0x00, 0x00, 0x00, // null address item
		0xB2, 0x00,             // unconnected data item
		byte(len(cipReq)), 0x00, // length
	}, cipReq...)
	h := make([]byte, 24)
	binary.LittleEndian.PutUint16(h[0:], 0x0065) // SendRRData
	binary.LittleEndian.PutUint16(h[2:], uint16(len(encapData)))
	binary.LittleEndian.PutUint32(h[4:], sessionHandle)
	return append(h, encapData...)
}

func parseListIdentity(data []byte) (string, uint16, uint16) {
	if len(data) < 60 {
		return "", 0, 0
	}
	// Skip EIP header (24 bytes) + CPF item header
	// ListIdentity response: offset 26 = item type 0x000C (Identity), then data
	offset := 26
	for offset+4 < len(data) {
		itemType := binary.LittleEndian.Uint16(data[offset:])
		itemLen := int(binary.LittleEndian.Uint16(data[offset+2:]))
		if itemType == 0x000C && offset+4+itemLen <= len(data) {
			// Identity item: 2 protocol, 4 socket, 2 vendorID, 2 deviceType, 2 productCode, 4 revision, 2 status, 4 serial, 1 nameLen, name
			iData := data[offset+4 : offset+4+itemLen]
			if len(iData) < 16 {
				return "", 0, 0
			}
			vendorID := binary.LittleEndian.Uint16(iData[6:])
			deviceType := binary.LittleEndian.Uint16(iData[8:])
			if len(iData) > 15 {
				nameLen := int(iData[15])
				if 16+nameLen <= len(iData) {
					name := string(iData[16 : 16+nameLen])
					return name, vendorID, deviceType
				}
			}
			return "", vendorID, deviceType
		}
		offset += 4 + itemLen
	}
	return "", 0, 0
}

func extractCIPStrings(data []byte) []string {
	var result []string
	seen := map[string]bool{}
	cur := []byte{}
	for _, b := range data {
		if b >= 0x20 && b <= 0x7E {
			cur = append(cur, b)
		} else {
			if len(cur) >= 3 && len(cur) <= 40 {
				s := string(cur)
				if !seen[s] {
					seen[s] = true
					result = append(result, s)
				}
			}
			cur = cur[:0]
		}
	}
	return result
}

func hexDumpEIP(b []byte) string {
	if len(b) > 48 {
		b = b[:48]
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
