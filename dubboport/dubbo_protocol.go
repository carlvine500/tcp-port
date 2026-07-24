package dubboport

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Dubbo protocol constants.
const (
	DubboMagicNumber   uint16 = 0xdabb
	DubboHeaderSize           = 16

	// Flag bits
	FlagSerializationMask byte = 0x1f // bits 0-4
	FlagTwoway           byte = 0x20 // bit 5: request is twoway (expects response)
	FlagEvent            byte = 0x40 // bit 6: is heartbeat event
)

// DubboHeader represents the 16-byte Dubbo protocol header.
type DubboHeader struct {
	Magic           uint16            // magic number 0xdabb
	Flag            byte              // serialization + twoway + event flags
	Status          byte              // response status, 0 for request
	RequestID       uint64            // request ID
	DataLength      uint32            // body length

	// Parsed from Flag
	SerializationID SerializationType
	IsTwoway       bool
	IsEvent        bool
	IsRequest      bool // true=request, false=response (derived from status==0)
}

// ParseDubboHeader parses a 16-byte Dubbo protocol header.
func ParseDubboHeader(data []byte) (*DubboHeader, error) {
	if len(data) < DubboHeaderSize {
		return nil, fmt.Errorf("dubbo header too short: %d bytes", len(data))
	}

	h := &DubboHeader{}
	h.Magic = binary.BigEndian.Uint16(data[0:2])
	if h.Magic != DubboMagicNumber {
		return nil, fmt.Errorf("not dubbo protocol: magic=0x%04x", h.Magic)
	}

	h.Flag = data[2]
	h.Status = data[3]
	h.RequestID = binary.BigEndian.Uint64(data[4:12])
	h.DataLength = binary.BigEndian.Uint32(data[12:16])

	// Parse flag
	h.SerializationID = SerializationType(h.Flag & FlagSerializationMask)
	h.IsTwoway = (h.Flag & FlagTwoway) != 0
	h.IsEvent = (h.Flag & FlagEvent) != 0
	h.IsRequest = h.Status == 0 // status=0 means request

	return h, nil
}

// DubboMessage represents a complete Dubbo protocol message.
type DubboMessage struct {
	Header *DubboHeader
	Body   []byte

	// Parsed body fields (best effort from Hessian2)
	ServiceName    string
	ServiceVersion string
	MethodName     string
	ParamTypes     string // comma-separated parameter type descriptors

	// For response
	ResponseStatus string // human-readable status
	HasException   bool
}

// ParseDubboBody performs best-effort parsing of Dubbo body to extract
// service/method metadata without full deserialization.
func (m *DubboMessage) ParseDubboBody() {
	// For heartbeat events, still parse body to get service name
	if m.Header.IsEvent && m.Header.IsRequest {
		m.parseRequestMetadata()
		if m.MethodName == "" {
			m.MethodName = "heartbeat"
		}
		return
	}

	if !m.Header.IsRequest {
		m.ResponseStatus = StatusString(m.Header.Status)
		// Try to detect exception
		m.HasException = m.Header.Status != StatusOK
		return
	}

	// Normal request: parse service/method from body
	m.parseRequestMetadata()
}

// parseRequestMetadata extracts service/method from body using simple
// string scanning. Dubbo request body format (Hessian2):
//
//	0x02 (Hessian2 version)
//	dubbo_version (string tag + value)
//	service_name (string tag + value)
//	service_version (string tag + value)
//	method_name (string tag + value)
//	param_type_desc (string tag + value)
//	arguments...
//	attachments (map)
func (m *DubboMessage) parseRequestMetadata() {
	if len(m.Body) < 2 {
		return
	}

	// Skip Hessian version byte
	pos := 1

	// Try to read dubbo version, service name, service version, method name, param types
	// Hessian2 string: tag 0x00-0x1f (short) or 0x30-0x33 (long) or 'S' 0x53 or 's' 0x73
	strings := make([]string, 0, 5)
	for i := 0; i < 6 && pos < len(m.Body); i++ {
		s, next := readHessian2String(m.Body, pos)
		if next < 0 {
			break
		}
		strings = append(strings, s)
		pos = next
	}

	if len(strings) >= 4 {
		// strings[0] = dubbo_version
		m.ServiceName = strings[1]
		m.ServiceVersion = strings[2]
		m.MethodName = strings[3]
	}
	if len(strings) >= 5 {
		m.ParamTypes = strings[4]
	}
}

// readHessian2String reads a Hessian2 encoded string from data at pos.
// Returns (string value, next position) or ("", -1) on failure.
func readHessian2String(data []byte, pos int) (string, int) {
	if pos >= len(data) {
		return "", -1
	}

	tag := data[pos]
	pos++

	switch {
	case tag >= 0x00 && tag <= 0x1f:
		// Short string, 0-31 bytes
		length := int(tag)
		if pos+length > len(data) {
			return "", -1
		}
		s := string(data[pos : pos+length])
		return s, pos + length

	case tag == 0x30:
		// String with 1-byte length (0-255)
		if pos >= len(data) {
			return "", -1
		}
		length := int(data[pos])
		pos++
		if pos+length > len(data) {
			return "", -1
		}
		s := string(data[pos : pos+length])
		return s, pos + length

	case tag == 0x31:
		// String with 2-byte length
		if pos+2 > len(data) {
			return "", -1
		}
		length := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		pos += 2
		if pos+length > len(data) {
			return "", -1
		}
		s := string(data[pos : pos+length])
		return s, pos + length

	case tag == 0x32 || tag == 0x33:
		// String with 4-byte length
		if pos+4 > len(data) {
			return "", -1
		}
		length := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if pos+length > len(data) {
			return "", -1
		}
		s := string(data[pos : pos+length])
		return s, pos + length

	default:
		// Not a string tag
		return "", -1
	}
}

// DetectDubbo reads enough bytes to detect if this is a Dubbo protocol stream.
func DetectDubbo(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return binary.BigEndian.Uint16(data[0:2]) == DubboMagicNumber
}

// ReadDubboMessage reads a complete Dubbo message from a reader.
// Returns header and body bytes.
func ReadDubboMessage(r io.Reader) (*DubboMessage, error) {
	// Read header
	headerBuf := make([]byte, DubboHeaderSize)
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, err
	}

	header, err := ParseDubboHeader(headerBuf)
	if err != nil {
		return nil, err
	}

	// Read body
	body := make([]byte, header.DataLength)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("dubbo body read error: %w", err)
	}

	msg := &DubboMessage{
		Header: header,
		Body:   body,
	}
	msg.ParseDubboBody()
	return msg, nil
}
