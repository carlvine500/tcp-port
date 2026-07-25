package dubboport

import (
	"encoding/binary"
	"fmt"
	"io"
	"unicode"
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
	Magic           uint16 // magic number 0xdabb
	Flag            byte   // serialization + twoway + event flags
	Status          byte   // response status, 0 for request
	RequestID       uint64 // request ID
	DataLength      uint32 // body length

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

	// Parsed body fields
	ServiceName    string
	ServiceVersion string
	MethodName     string
	ParamTypes     string // comma-separated parameter type descriptors

	// For response
	ResponseStatus string // human-readable status
	HasException   bool

	// Metadata
	IsRealHeartbeat bool // true only if body is very small (< 50 bytes)
}

// ParseDubboBody performs best-effort parsing of Dubbo body.
func (m *DubboMessage) ParseDubboBody() {
	if !m.Header.IsRequest {
		m.ResponseStatus = StatusString(m.Header.Status)
		m.HasException = m.Header.Status != StatusOK
		return
	}

	// Detect real heartbeat: IsEvent + tiny body
	m.IsRealHeartbeat = m.Header.IsEvent && len(m.Body) <= 50

	// For compactedjava serialization (Dubbo 2.5.x), use string scanning
	if m.Header.SerializationID == SerializationCompactedJava {
		m.parseCompactedJavaBody()
	} else {
		m.parseRequestMetadata()
	}

	// Still empty? Try generic string scan as fallback
	if m.ServiceName == "" && m.MethodName == "" && len(m.Body) > 2 {
		m.parseGenericBody()
	}

	// Label unknown events
	if m.Header.IsEvent && m.MethodName == "" {
		if m.IsRealHeartbeat {
			m.MethodName = "heartbeat"
		} else {
			m.MethodName = "(event)"
		}
	}
}

// parseCompactedJavaBody extracts service/method from compactedjava serialized body.
// The body contains Java serialization data with class descriptors.
// We scan for readable ASCII sequences that look like class names and method names.
func (m *DubboMessage) parseCompactedJavaBody() {
	strings := extractReadableStrings(m.Body, 5) // min length 5
	if len(strings) == 0 {
		return
	}

	// Find service name: longest string containing '.' (Java fully-qualified class name)
	// In Dubbo 2.5.x compactedjava, the service interface appears as a class descriptor
	for _, s := range strings {
		if containsDot(s) && len(s) > len(m.ServiceName) && !looksLikeMethodOrParam(s) {
			m.ServiceName = s
		}
	}

	// If no dotted name found, take the first long alphanumeric string as service
	if m.ServiceName == "" {
		for _, s := range strings {
			if len(s) >= 8 && isAlphanumericDot(s) {
				m.ServiceName = s
				break
			}
		}
	}

	// Find method name: short readable string that looks like a Java method
	for _, s := range strings {
		if m.MethodName == "" && isJavaMethodName(s) && s != m.ServiceName {
			m.MethodName = s
			break
		}
	}
}

// parseGenericBody scans any body for readable strings as last-resort fallback.
func (m *DubboMessage) parseGenericBody() {
	strings := extractReadableStrings(m.Body, 4)
	for _, s := range strings {
		if containsDot(s) && m.ServiceName == "" {
			m.ServiceName = s
		}
		if isJavaMethodName(s) && m.MethodName == "" && s != m.ServiceName {
			m.MethodName = s
		}
	}
}

// parseRequestMetadata extracts service/method from body using Hessian2 string parsing.
func (m *DubboMessage) parseRequestMetadata() {
	if len(m.Body) < 2 {
		return
	}

	// Skip Hessian version byte
	pos := 1

	// Read up to 6 Hessian2-encoded strings from the body
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
		m.ServiceName = strings[1]
		m.ServiceVersion = strings[2]
		m.MethodName = strings[3]
	}
	if len(strings) >= 5 {
		m.ParamTypes = strings[4]
	}
}

// ---- Utility functions ----

// extractReadableStrings scans a byte slice and extracts all sequences
// of printable ASCII characters (letters, digits, dots, underscores, slashes)
// that are at least minLen characters long. Sorted by position.
func extractReadableStrings(data []byte, minLen int) []string {
	var result []string
	start := -1
	for i, b := range data {
		if isReadable(b) {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 && i-start >= minLen {
				result = append(result, string(data[start:i]))
			}
			start = -1
		}
	}
	if start >= 0 && len(data)-start >= minLen {
		result = append(result, string(data[start:]))
	}
	return result
}

// isReadable returns true for printable ASCII chars commonly found in class/method names.
func isReadable(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '.' || b == '_' || b == '/' || b == '$'
}

func isAlphanumericDot(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '_' && r != '$' && r != '/' {
			return false
		}
	}
	return true
}

func containsDot(s string) bool {
	for _, r := range s {
		if r == '.' {
			return true
		}
	}
	return false
}

// looksLikeMethodOrParam returns true if the string looks like a method name
// or parameter descriptor rather than a class name.
func looksLikeMethodOrParam(s string) bool {
	// Method names: start with lowercase, short, no dots
	if len(s) < 2 {
		return true
	}
	first := rune(s[0])
	return unicode.IsLower(first) || s[0] == '(' || s[0] == '[' || s[0] == 'L'
}

// isJavaMethodName returns true if s looks like a Java method name.
func isJavaMethodName(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !unicode.IsLower(r) && r != '_' && r != '$' {
				return false
			}
		} else {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '$' {
				return false
			}
		}
	}
	return true
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
