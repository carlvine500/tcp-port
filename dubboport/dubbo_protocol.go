package dubboport

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// Dubbo protocol constants.
const (
	DubboMagicNumber uint16 = 0xdabb
	DubboHeaderSize         = 16

	// Flag bits — Alibaba Dubbo layout (legacy 2.5.x)
	FlagSerializationMask byte = 0x1f // bits 0-4
	FlagTwoway            byte = 0x20 // bit 5: request is twoway (expects response)
	FlagEvent             byte = 0x40 // bit 6: is heartbeat event

	// Flag bits — Apache Dubbo layout (2.7.x / 3.x)
	// In Apache Dubbo, Twoway and Event bits are SWAPPED:
	//   FLAG_TWOWAY = 0x40 (bit 6)
	//   FLAG_EVENT  = 0x20 (bit 5)
	FlagApacheTwoway byte = 0x40
	FlagApacheEvent  byte = 0x20
)

// DubboHeader represents the 16-byte Dubbo protocol header.
type DubboHeader struct {
	Magic      uint16 // magic number 0xdabb
	Flag       byte   // serialization + twoway + event flags
	Status     byte   // response status, 0 for request
	RequestID  uint64 // request ID
	DataLength uint32 // body length

	// Parsed from Flag
	SerializationID SerializationType
	IsTwoway        bool
	IsEvent         bool
	IsRequest       bool // true=request, false=response (derived from status==0)
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

	// Parse flag (Alibaba Dubbo layout by default)
	h.SerializationID = SerializationType(h.Flag & FlagSerializationMask)
	h.IsTwoway = (h.Flag & FlagTwoway) != 0
	h.IsEvent = (h.Flag & FlagEvent) != 0
	h.IsRequest = h.Status == 0 // status=0 means request

	return h, nil
}

// fixupFlags detects and corrects the flag-bit layout when it appears
// to be Apache Dubbo (where Twoway=0x40, Event=0x20) rather than
// Alibaba Dubbo (where Twoway=0x20, Event=0x40).
//
// Heuristic: a request with IsEvent=true AND a large body (>50 bytes)
// is almost certainly NOT a real heartbeat. In that case the bits are
// likely swapped (Apache layout). We re-interpret the flag byte and
// swap back if the alternative reading gives Twoway=true + Event=false.
func (h *DubboHeader) fixupFlags() {
	if !h.IsRequest || h.DataLength <= 50 {
		return
	}

	// Already looks reasonable — twoway RPC, no event bit
	if h.IsTwoway && !h.IsEvent {
		return
	}

	// IsEvent=true with a large body is suspicious.
	// Try Apache Dubbo layout: Twoway at 0x40, Event at 0x20.
	apacheTwoway := (h.Flag & FlagApacheTwoway) != 0
	apacheEvent := (h.Flag & FlagApacheEvent) != 0

	// If Apache layout gives Twoway=true and Event=false,
	// and the body is large enough to be a real RPC, adopt it.
	if apacheTwoway && !apacheEvent && h.DataLength > 50 {
		h.IsTwoway = apacheTwoway
		h.IsEvent = apacheEvent
		return
	}

	// If the current layout already has Twoway=false + Event=true
	// and Apache layout doesn't improve it, try a third heuristic:
	// if body > 200 bytes and both layouts disagree, prefer Apache.
	if h.DataLength > 200 {
		if apacheTwoway != h.IsTwoway || apacheEvent != h.IsEvent {
			// Large body — prefer the layout that says twoway=true
			if apacheTwoway && !h.IsTwoway {
				h.IsTwoway = apacheTwoway
				h.IsEvent = apacheEvent
			}
		}
	}
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

	// Parsed request parameters (from compactedjava body)
	Params      []KVPair // request parameter names (best-effort)
	Attachments []KVPair // attachment key-value pairs from body

	// Parsed argument values from Java deserializer (compactedjava only)
	ParsedArgs  map[string]interface{} // field-name → value map
	ArgStartPos int                    // byte offset where Java serialization args begin

	// Metadata
	IsRealHeartbeat bool // true only if body is very small (< 50 bytes)
	ShowBody        bool // if true, display parsed body fields
}

// KVPair is a key-value pair from the body.
type KVPair struct {
	Key   string
	Value string
}

// ParseDubboBody performs best-effort parsing of Dubbo body.
func (m *DubboMessage) ParseDubboBody() {
	// Auto-detect and fix flag-bit layout (Alibaba vs Apache Dubbo).
	// Apache Dubbo swaps the Twoway (0x40) and Event (0x20) bits,
	// which would otherwise cause all RPCs to be mis-read as one-way events.
	m.Header.fixupFlags()

	if !m.Header.IsRequest {
		m.ResponseStatus = StatusString(m.Header.Status)
		m.HasException = m.Header.Status != StatusOK
		return
	}

	// Detect real heartbeat: IsEvent + tiny body (≤50 bytes).
	// A genuine Dubbo heartbeat has a 1-byte body (single null).
	m.IsRealHeartbeat = m.Header.IsEvent && len(m.Body) <= 50

	// Parse body based on serialization type.
	switch m.Header.SerializationID {
	case SerializationCompactedJava:
		// CompactedJava uses its own string encoding (2-byte len prefix).
		// Try the structured parser first, then fall back to heuristic.
		m.parseCompactedJavaDirect()
		if m.ServiceName == "" && m.MethodName == "" {
			m.parseCompactedJavaBody()
		}
	case SerializationHessian2, SerializationHessian1:
		m.parseRequestMetadata()
	default:
		// For kryo, protobuf, fastjson, etc. we can't parse the body
		// without full deserialization. Fall back to generic string scan.
		m.parseGenericBody()
	}

	// Still empty after type-specific parsing? Try generic fallback.
	if m.ServiceName == "" && m.MethodName == "" && len(m.Body) > 2 {
		m.parseGenericBody()
	}

	// Clean up compactedjava encoding artifacts from service/method names
	if m.ServiceName != "" {
		m.ServiceName = cleanClassName(m.ServiceName)
	}
	if m.MethodName != "" {
		m.MethodName = cleanMethodName(m.MethodName)
	}

	// For compactedjava: if ServiceName is still empty or was polluted by
	// garbage number strings, run parseCompactedJavaBody as a fallback.
	// It scans the raw body for real class names like "com.bizcloud...".
	if m.Header.SerializationID == SerializationCompactedJava &&
		(m.ServiceName == "" || isNumericDotOnly(m.ServiceName)) {
		savedName := m.ServiceName
		m.ServiceName = "" // reset so parseCompactedJavaBody can fill it
		m.parseCompactedJavaBody()
		if m.ServiceName == "" && savedName != "" {
			m.ServiceName = savedName // keep original if fallback failed
		}
	}

	// For compactedjava: try to deserialize Java args from the body
	// after the compactedjava header strings.
	if m.Header.SerializationID == SerializationCompactedJava &&
		m.ArgStartPos > 0 && m.ArgStartPos < len(m.Body) {
		parsed, err := ParseJavaSerializedArgs(m.Body, m.ArgStartPos)
		if err == nil && len(parsed) > 0 {
			m.ParsedArgs = parsed
		}
	}

	// Extract parameter names and attachments from body
	if m.Header.IsRequest && len(m.Body) > 4 {
		m.parseBodyParams()
	}

	// Label events that we couldn't identify.
	if m.Header.IsEvent && m.MethodName == "" {
		if m.IsRealHeartbeat {
			m.MethodName = "heartbeat"
		} else {
			m.MethodName = "(event)"
		}
	}
}

// parseCompactedJavaDirect reads strings using the compactedjava format:
// 2-byte big-endian unsigned short length + UTF-8 bytes.
// In Dubbo 2.5.x compactedjava, the body typically starts with:
//
//	dubbo_version  (UTF string)
//	service_name   (UTF string)
//	service_version (UTF string)
//	method_name    (UTF string)
//	param_types    (UTF string)
//	arguments...   (Java serialization)
//	attachments... (Java serialization)
func (m *DubboMessage) parseCompactedJavaDirect() {
	if len(m.Body) < 2 {
		return
	}

	pos := 0
	strings := make([]string, 0, 6)
	for i := 0; i < 8 && pos+2 <= len(m.Body); i++ {
		length := int(binary.BigEndian.Uint16(m.Body[pos : pos+2]))
		pos += 2
		if length <= 0 || length > 10000 || pos+length > len(m.Body) {
			break
		}
		s := string(m.Body[pos : pos+length])
		pos += length
		// Only accept printable ASCII strings (likely real field names)
		if isReadableString(s) {
			strings = append(strings, s)
		}
	}

	// Record where the Java serialization stream starts (after header strings).
	m.ArgStartPos = pos

	if len(strings) >= 4 {
		// strings[0] = dubbo version (e.g. "2.0.2")
		// strings[1] = service name (e.g. "com.example.DemoService")
		// strings[2] = service version (e.g. "1.0.0")
		// strings[3] = method name (e.g. "sayHello")
		// strings[4] = param types (e.g. "Ljava/lang/String;")
		if isNumericDotOnly(strings[1]) {
			// strings[1] is garbage; try shifted layout
			if len(strings) >= 5 && containsDot(strings[2]) {
				m.ServiceName = strings[2]
				m.ServiceVersion = strings[3]
				m.MethodName = strings[4]
			}
		} else if containsDot(strings[1]) || strings[1] == strings[0] {
			// strings[1] looks like a service name OR same as dubbo version
			// (in some Dubbo versions the fields might be shifted)
			if containsDot(strings[1]) {
				m.ServiceName = strings[1]
				m.ServiceVersion = strings[2]
				m.MethodName = strings[3]
			} else if len(strings) >= 5 && containsDot(strings[2]) {
				// Shifted: dubbo_ver at [0], service at [2], method at [4]
				m.ServiceName = strings[2]
				m.ServiceVersion = strings[3]
				m.MethodName = strings[4]
			}
		} else if containsDot(strings[2]) {
			m.ServiceName = strings[2]
			m.ServiceVersion = strings[3]
			m.MethodName = strings[4] // or maybe strings[1]?
		} else {
			// Try alternate: find the first dotted string as service
			for i, s := range strings {
				if containsDot(s) && m.ServiceName == "" && !isNumericDotOnly(s) {
					m.ServiceName = s
					if i+1 < len(strings) && !containsDot(strings[i+1]) {
						m.ServiceVersion = strings[i+1]
					}
					if i+2 < len(strings) {
						m.MethodName = strings[i+2]
					}
				}
			}
		}
		if len(strings) >= 5 {
			m.ParamTypes = strings[len(strings)-1] // last string is often param types
		}
	}
}

// isReadableString returns true if s consists only of printable ASCII
// characters commonly found in class/method/version names.
func isReadableString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
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

// cleanClassName strips garbage prefixes that compactedjava encoding
// can introduce before the actual Java class name.
// Examples:
//
//	"SNAPSHOT04com.bizcloud.Foo" → "com.bizcloud.Foo"
//	"C0Wcom.successchannel.Bar" → "com.successchannel.Bar"
//	"1.20762000000.17849900595990004" → "" (pure number-dot garbage)
func cleanClassName(s string) string {
	if s == "" {
		return s
	}
	// Pure number-dot strings are garbage (e.g. "1.20762000000.17850216178280004")
	if isNumericDotOnly(s) {
		return ""
	}
	// Find first occurrence of a known Java package prefix
	for _, prefix := range []string{"com.", "org.", "cn.", "net.", "io.", "java.", "javax."} {
		if idx := strings.Index(s, prefix); idx >= 0 {
			return s[idx:]
		}
	}
	// If no recognized package prefix, try to strip leading non-alpha garbage
	// e.g., "C0W" + real_name, "SNAPSHOT04" + real_name
	for i, r := range s {
		if unicode.IsLetter(r) && i > 0 {
			// Check if from here forward looks like a class name
			rest := s[i:]
			if containsDot(rest) && len(rest) >= 10 {
				return rest
			}
		}
	}
	return s
}

// isNumericDotOnly returns true if s consists only of digits and dots.
func isNumericDotOnly(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// cleanMethodName strips trailing digits/type-markers from method names.
// Examples: "containsAdminFunction0" → "containsAdminFunction"
//
//	"getButton0" → "getButton"
func cleanMethodName(s string) string {
	if s == "" {
		return s
	}
	// Strip trailing digits that aren't part of camelCase
	for len(s) > 1 && s[len(s)-1] >= '0' && s[len(s)-1] <= '9' {
		if s[len(s)-2] >= 'a' && s[len(s)-2] <= 'z' {
			s = s[:len(s)-1]
		} else {
			break
		}
	}
	return s
}

// parseBodyParams extracts parameter names and attachment keys from
// a compactedjava Dubbo body using string scanning heuristics.
// Parameters appear as readable field names in the body after the
// initial header fields (version, service, method, param types).
// Attachments appear near the end as key-value pairs.
//
// When ParsedArgs is available (Java deserialization succeeded for the
// arguments), we skip the string-scanning heuristic for attachments and
// use ParseJavaSerializedAttachments to properly decode the HashMap
// that compactedjava uses for attachment storage. This avoids the
// garbled KV pairs caused by binary data interleaving.
func (m *DubboMessage) parseBodyParams() {
	if len(m.Body) < 4 {
		return
	}

	// For compactedjava with successfully-deserialized args, use the
	// Java deserializer for attachments too — the string-scanning
	// heuristic produces garbled KV pairs on binary-interleaved data.
	if m.ParsedArgs != nil && m.Header.SerializationID == SerializationCompactedJava {
		m.parseAttachmentsFromJava()
		// Still extract parameter names via string scanning below
	}

	// Extract all readable strings from the body
	allStrings := extractReadableStrings(m.Body, 2)

	// Find the "attachment boundary" — where field names switch from
	// parameter names to attachment keys. Common attachment prefixes
	// start with underscore or are kebab-case / camelCase keywords.
	attachStart := len(allStrings)
	for i, s := range allStrings {
		if len(s) >= 3 && (strings.HasPrefix(s, "_") ||
			s == "interface" || s == "path" || s == "timeout" ||
			s == "version" || s == "sw8" || strings.HasPrefix(s, "sw8-") ||
			s == "accesslog" || s == "custom-request-response-id") {
			attachStart = i
			break
		}
	}

	// Extract parameter names (camelCase, no underscores, not version/service/method)
	seen := map[string]bool{m.ServiceName: true, m.MethodName: true, m.ServiceVersion: true}
	for i := 0; i < attachStart && i < len(allStrings); i++ {
		s := allStrings[i]
		if seen[s] || len(s) < 2 || len(s) > 50 {
			continue
		}
		if isJavaFieldName(s) {
			m.Params = append(m.Params, KVPair{Key: s})
			seen[s] = true
		}
	}

	// Skip string-scanning attachments if we already parsed them via Java
	if m.ParsedArgs != nil && m.Header.SerializationID == SerializationCompactedJava {
		return
	}

	// Extract attachment key-value pairs (pairs of strings)
	for i := attachStart; i+1 < len(allStrings); i += 2 {
		key := allStrings[i]
		val := allStrings[i+1]
		// Skip obvious non-attachment keys
		if strings.Contains(key, ".") && len(key) > 30 {
			continue
		}
		if len(key) < 2 || len(key) > 50 {
			continue
		}
		// Skip if value looks like another key (too long)
		if len(val) > 60 {
			val = val[:60] + "..."
		}
		m.Attachments = append(m.Attachments, KVPair{Key: key, Value: val})
	}
}

// parseAttachmentsFromJava attempts to parse attachment key-value pairs
// from a compactedjava HashMap using the Java serialization deserializer.
func (m *DubboMessage) parseAttachmentsFromJava() {
	if m.ArgStartPos <= 0 || m.ArgStartPos >= len(m.Body) {
		return
	}
	attachMap, err := ParseJavaSerializedAttachments(m.Body, m.ArgStartPos)
	if err != nil || len(attachMap) == 0 {
		return
	}
	for k, v := range attachMap {
		m.Attachments = append(m.Attachments, KVPair{Key: k, Value: v})
	}
}

// isJavaFieldName returns true if s looks like a Java field name (camelCase).
func isJavaFieldName(s string) bool {
	if len(s) < 2 || strings.Contains(s, ".") {
		return false
	}
	first := rune(s[0])
	if !unicode.IsLower(first) {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

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
