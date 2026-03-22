// Package modbusdeep performs deep Modbus scanning by reading coils and registers.
package modbusdeep

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

var ErrNoResponse = errors.New("modbusdeep: no response")

type RegisterSet struct {
	FC     int    `json:"fc"`
	Name   string `json:"name"`
	Values []int  `json:"values"`
	Error  string `json:"error,omitempty"`
}

type Result struct {
	IP        string        `json:"ip"`
	Port      int           `json:"port"`
	Registers []RegisterSet `json:"registers"`
}

func Scan(ip string) (*Result, error) {
	result := &Result{IP: ip, Port: 502}
	type fcInfo struct {
		fc   byte
		name string
	}
	fcs := []fcInfo{
		{0x01, "Read Coils"},
		{0x02, "Read Discrete Inputs"},
		{0x03, "Read Holding Registers"},
		{0x04, "Read Input Registers"},
	}
	anyResponse := false
	for _, f := range fcs {
		rs := readModbus(ip, f.fc, f.name)
		result.Registers = append(result.Registers, rs)
		if rs.Error == "" {
			anyResponse = true
		}
	}
	if !anyResponse {
		return nil, ErrNoResponse
	}
	return result, nil
}

func readModbus(ip string, fc byte, name string) RegisterSet {
	rs := RegisterSet{FC: int(fc), Name: name}
	addr := fmt.Sprintf("%s:502", ip)
	conn, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		rs.Error = err.Error()
		return rs
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// MBAP header (7 bytes) + PDU (5 bytes)
	req := make([]byte, 12)
	binary.BigEndian.PutUint16(req[0:], 0x0001) // Transaction ID
	binary.BigEndian.PutUint16(req[2:], 0x0000) // Protocol ID (Modbus)
	binary.BigEndian.PutUint16(req[4:], 0x0006) // Length
	req[6] = 0xFF                               // Unit ID
	req[7] = fc                                 // Function code
	binary.BigEndian.PutUint16(req[8:], 0x0000) // Start address
	binary.BigEndian.PutUint16(req[10:], 0x000A) // Quantity (10)

	if _, err := conn.Write(req); err != nil {
		rs.Error = err.Error()
		return rs
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 9 {
		rs.Error = "no valid response"
		return rs
	}

	// Check for exception response
	if buf[7]&0x80 != 0 {
		rs.Error = fmt.Sprintf("Modbus exception code %d", buf[8])
		return rs
	}

	byteCount := int(buf[8])
	data := buf[9 : 9+byteCount]

	if fc == 0x01 || fc == 0x02 {
		// Bit values - extract each bit
		for i := 0; i < 10 && i/8 < len(data); i++ {
			bit := (data[i/8] >> uint(i%8)) & 0x01
			rs.Values = append(rs.Values, int(bit))
		}
	} else {
		// Word values (FC3/FC4)
		for i := 0; i+1 < len(data); i += 2 {
			val := int(binary.BigEndian.Uint16(data[i:]))
			rs.Values = append(rs.Values, val)
		}
	}
	return rs
}
