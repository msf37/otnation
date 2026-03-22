// Package snmp provides a minimal SNMPv2c enumerator that probes common
// community strings and retrieves basic system OIDs using raw UDP without
// any external SNMP library.
package snmp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// ErrNoData is returned when no community string produces a valid response.
var ErrNoData = errors.New("snmp: no response from any community string")

// Result holds the data retrieved from a successful SNMPv2c query.
type Result struct {
	Community   string `json:"community"`
	SysDescr    string `json:"sys_descr"`
	SysName     string `json:"sys_name"`
	SysLocation string `json:"sys_location"`
	SysContact  string `json:"sys_contact"`
	SysUpTime   string `json:"sys_uptime"`
}

// Community strings to try in order.
var communities = []string{
	"public", "private", "community", "admin", "cisco", "manager", "snmp",
}

// OID bytes for the five system MIB leaf nodes (pre-encoded as BER OID values).
var sysOIDs = []struct {
	name string
	oid  []byte
}{
	{"sysDescr", []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}},
	{"sysName", []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00}},
	{"sysLocation", []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00}},
	{"sysContact", []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x00}},
	{"sysUpTime", []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00}},
}

// Enumerate probes the target IP over UDP/161 trying each community string.
// Returns the first successful Result, or ErrNoData if nothing responds.
func Enumerate(ctx context.Context, ip string) (*Result, error) {
	for _, community := range communities {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		result, err := tryEnumerate(ctx, ip, community)
		if err == nil && result != nil {
			return result, nil
		}
	}
	return nil, ErrNoData
}

// tryEnumerate sends a single SNMPv2c GetRequest for all five OIDs using the
// provided community string and parses the response.
func tryEnumerate(ctx context.Context, ip, community string) (*Result, error) {
	addr := net.JoinHostPort(ip, "161")
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Build the PDU.
	pdu := buildGetRequest(community, 1, sysOIDs)

	// Set deadline from context or 3-second timeout.
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline) //nolint:errcheck

	if _, err := conn.Write(pdu); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	values, err := parseGetResponse(buf[:n])
	if err != nil {
		return nil, err
	}

	result := &Result{Community: community}
	for i, oid := range sysOIDs {
		if i < len(values) {
			switch oid.name {
			case "sysDescr":
				result.SysDescr = values[i]
			case "sysName":
				result.SysName = values[i]
			case "sysLocation":
				result.SysLocation = values[i]
			case "sysContact":
				result.SysContact = values[i]
			case "sysUpTime":
				result.SysUpTime = values[i]
			}
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Minimal BER encoder/decoder
// ---------------------------------------------------------------------------

// tlv writes a BER TLV (tag-length-value) to a byte slice.
func tlv(tag byte, value []byte) []byte {
	length := len(value)
	var lenBytes []byte
	if length < 0x80 {
		lenBytes = []byte{byte(length)}
	} else if length <= 0xFF {
		lenBytes = []byte{0x81, byte(length)}
	} else {
		lenBytes = []byte{0x82, byte(length >> 8), byte(length)}
	}
	out := []byte{tag}
	out = append(out, lenBytes...)
	out = append(out, value...)
	return out
}

// encodeInt encodes a Go int as BER INTEGER value bytes (no tag).
func encodeInt(v int) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	// Strip leading zero bytes but keep at least one.
	i := 0
	for i < 3 && b[i] == 0x00 {
		i++
	}
	return b[i:]
}

// buildVarBind builds a VarBind for a GET (null value).
func buildVarBind(oid []byte) []byte {
	oidTLV := tlv(0x06, oid) // OID tag = 0x06
	nullTLV := tlv(0x05, nil) // NULL tag = 0x05
	vb := append(oidTLV, nullTLV...)
	return tlv(0x30, vb) // SEQUENCE
}

// buildGetRequest encodes a minimal SNMPv2c GetRequest PDU.
func buildGetRequest(community string, requestID int, oids []struct {
	name string
	oid  []byte
}) []byte {
	// Version: SNMPv2c = 1
	version := tlv(0x02, encodeInt(1))
	// Community
	comm := tlv(0x04, []byte(community))

	// VarBindList
	var varBinds []byte
	for _, o := range oids {
		varBinds = append(varBinds, buildVarBind(o.oid)...)
	}
	varBindList := tlv(0x30, varBinds)

	reqID := tlv(0x02, encodeInt(requestID))
	errStatus := tlv(0x02, encodeInt(0))
	errIndex := tlv(0x02, encodeInt(0))

	pduBody := append(reqID, errStatus...)
	pduBody = append(pduBody, errIndex...)
	pduBody = append(pduBody, varBindList...)

	// GetRequest PDU tag = 0xA0
	pdu := tlv(0xA0, pduBody)

	msg := append(version, comm...)
	msg = append(msg, pdu...)
	return tlv(0x30, msg) // outer SEQUENCE
}

// ---------------------------------------------------------------------------
// BER response parser
// ---------------------------------------------------------------------------

// readLength reads a BER length field starting at buf[pos] and returns
// the parsed length and the new pos after the length bytes.
func readLength(buf []byte, pos int) (int, int, error) {
	if pos >= len(buf) {
		return 0, pos, errors.New("snmp: buffer too short for length")
	}
	first := buf[pos]
	pos++
	if first&0x80 == 0 {
		return int(first), pos, nil
	}
	numOctets := int(first & 0x7F)
	if pos+numOctets > len(buf) {
		return 0, pos, errors.New("snmp: buffer too short for long length")
	}
	length := 0
	for i := 0; i < numOctets; i++ {
		length = (length << 8) | int(buf[pos])
		pos++
	}
	return length, pos, nil
}

// skipTLV skips one complete TLV element, returning pos after it.
func skipTLV(buf []byte, pos int) (int, error) {
	if pos >= len(buf) {
		return pos, errors.New("snmp: unexpected end")
	}
	pos++ // skip tag
	length, pos, err := readLength(buf, pos)
	if err != nil {
		return pos, err
	}
	return pos + length, nil
}

// parseGetResponse extracts the string value of each VarBind in the response.
// It navigates: SEQUENCE > version + community + GetResponse-PDU > requestID +
// errStatus + errIndex + VarBindList > VarBind* > OID + value.
func parseGetResponse(buf []byte) ([]string, error) {
	pos := 0
	// outer SEQUENCE
	if pos >= len(buf) || buf[pos] != 0x30 {
		return nil, errors.New("snmp: expected outer SEQUENCE")
	}
	pos++
	_, pos, err := readLength(buf, pos)
	if err != nil {
		return nil, err
	}

	// skip version
	pos, err = skipTLV(buf, pos)
	if err != nil {
		return nil, err
	}
	// skip community
	pos, err = skipTLV(buf, pos)
	if err != nil {
		return nil, err
	}

	// GetResponse PDU (tag 0xA2)
	if pos >= len(buf) || buf[pos] != 0xA2 {
		return nil, errors.New("snmp: expected GetResponse PDU")
	}
	pos++
	_, pos, err = readLength(buf, pos)
	if err != nil {
		return nil, err
	}

	// skip requestID, errorStatus, errorIndex
	for i := 0; i < 3; i++ {
		pos, err = skipTLV(buf, pos)
		if err != nil {
			return nil, err
		}
	}

	// VarBindList SEQUENCE
	if pos >= len(buf) || buf[pos] != 0x30 {
		return nil, errors.New("snmp: expected VarBindList SEQUENCE")
	}
	pos++
	vblLen, pos, err := readLength(buf, pos)
	if err != nil {
		return nil, err
	}
	vblEnd := pos + vblLen

	var values []string
	for pos < vblEnd {
		// Each VarBind is a SEQUENCE
		if buf[pos] != 0x30 {
			break
		}
		pos++
		vbLen, newPos, err := readLength(buf, pos)
		if err != nil {
			return nil, err
		}
		pos = newPos
		vbEnd := pos + vbLen

		// skip OID
		pos, err = skipTLV(buf, pos)
		if err != nil {
			return nil, err
		}

		if pos >= vbEnd {
			values = append(values, "")
			pos = vbEnd
			continue
		}

		valueTag := buf[pos]
		pos++
		valueLen, pos, err := readLength(buf, pos)
		if err != nil {
			return nil, err
		}
		if pos+valueLen > len(buf) {
			return nil, errors.New("snmp: value length exceeds buffer")
		}
		valueBytes := buf[pos : pos+valueLen]
		pos += valueLen

		var strVal string
		switch valueTag {
		case 0x04: // OCTET STRING
			strVal = string(valueBytes)
		case 0x43: // TimeTicks
			var ticks uint32
			for _, b := range valueBytes {
				ticks = (ticks << 8) | uint32(b)
			}
			centiseconds := ticks
			seconds := centiseconds / 100
			days := seconds / 86400
			hours := (seconds % 86400) / 3600
			minutes := (seconds % 3600) / 60
			secs := seconds % 60
			strVal = formatUptime(days, hours, minutes, secs)
		case 0x02: // INTEGER
			var v int64
			for _, b := range valueBytes {
				v = (v << 8) | int64(b)
			}
			strVal = intToStr(v)
		default:
			strVal = bytesToHex(valueBytes)
		}
		values = append(values, strVal)
		pos = vbEnd
	}
	return values, nil
}

func formatUptime(days, hours, minutes, secs uint32) string {
	return uintToStr(days) + "d " + uintToStr(hours) + "h " + uintToStr(minutes) + "m " + uintToStr(secs) + "s"
}

func uintToStr(n uint32) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

func intToStr(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		return "-" + string(buf)
	}
	return string(buf)
}

func bytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*3)
	for i, v := range b {
		out[i*3] = hexChars[v>>4]
		out[i*3+1] = hexChars[v&0x0f]
		if i < len(b)-1 {
			out[i*3+2] = ':'
		}
	}
	if len(out) > 0 {
		return string(out[:len(out)-1])
	}
	return ""
}
