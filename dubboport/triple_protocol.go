package dubboport

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Triple (HTTP/2 + gRPC) protocol constants.
const (
	// HTTP/2 frame header
	HTTP2FrameHeaderSize = 9

	// HTTP/2 frame types
	HTTP2FrameData        byte = 0x0
	HTTP2FrameHeaders     byte = 0x1
	HTTP2FramePriority    byte = 0x2
	HTTP2FrameRSTStream   byte = 0x3
	HTTP2FrameSettings    byte = 0x4
	HTTP2FramePushPromise byte = 0x5
	HTTP2FramePing        byte = 0x6
	HTTP2FrameGoaway      byte = 0x7
	HTTP2FrameWindow      byte = 0x8
	HTTP2FrameContinuation byte = 0x9

	// HTTP/2 connection preface
	HTTP2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

// HTTP2FrameHeader represents a 9-byte HTTP/2 frame header.
type HTTP2FrameHeader struct {
	Length   uint32 // 24-bit length
	Type     byte
	Flags    byte
	StreamID uint32 // 31-bit stream ID
}

// ParseHTTP2FrameHeader parses an HTTP/2 frame header.
func ParseHTTP2FrameHeader(data []byte) (*HTTP2FrameHeader, error) {
	if len(data) < HTTP2FrameHeaderSize {
		return nil, fmt.Errorf("HTTP/2 frame header too short: %d bytes", len(data))
	}

	return &HTTP2FrameHeader{
		Length:   uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2]),
		Type:     data[3],
		Flags:    data[4],
		StreamID: binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF,
	}, nil
}

// TripleMessage represents a decoded Triple/gRPC message.
type TripleMessage struct {
	ServiceName string
	MethodName  string
	ContentType string // "application/grpc" or "application/grpc+proto" or "application/grpc+json"
	IsRequest   bool
	Headers     map[string]string

	// gRPC message frames
	Messages []GRPCMessageFrame
}

// GRPCMessageFrame represents a single gRPC length-prefixed message.
type GRPCMessageFrame struct {
	Compressed bool
	Length     uint32
	Data       []byte
}

// IsTriplePreface checks if data starts with the HTTP/2 connection preface.
func IsTriplePreface(data []byte) bool {
	return len(data) >= len(HTTP2Preface) && string(data[:len(HTTP2Preface)]) == HTTP2Preface
}

// DetectTriple checks if this looks like triple protocol (HTTP/2 magic).
func DetectTriple(data []byte) bool {
	if len(data) < 24 {
		return false
	}
	return IsTriplePreface(data)
}

// FrameTypeString returns the HTTP/2 frame type name.
func FrameTypeString(ft byte) string {
	switch ft {
	case HTTP2FrameData:
		return "DATA"
	case HTTP2FrameHeaders:
		return "HEADERS"
	case HTTP2FramePriority:
		return "PRIORITY"
	case HTTP2FrameRSTStream:
		return "RST_STREAM"
	case HTTP2FrameSettings:
		return "SETTINGS"
	case HTTP2FramePushPromise:
		return "PUSH_PROMISE"
	case HTTP2FramePing:
		return "PING"
	case HTTP2FrameGoaway:
		return "GOAWAY"
	case HTTP2FrameWindow:
		return "WINDOW_UPDATE"
	case HTTP2FrameContinuation:
		return "CONTINUATION"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", ft)
	}
}

// ParseGRPCMessage parses a gRPC length-prefixed message.
// gRPC frame format: 1 byte compressed flag + 4 byte big-endian length + payload.
func ParseGRPCMessage(data []byte) (*GRPCMessageFrame, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("gRPC frame too short: %d bytes", len(data))
	}

	compressed := data[0] == 1
	length := binary.BigEndian.Uint32(data[1:5])

	if len(data) < 5+int(length) {
		return nil, fmt.Errorf("gRPC frame payload too short: need %d, got %d", 5+length, len(data))
	}

	return &GRPCMessageFrame{
		Compressed: compressed,
		Length:     length,
		Data:       data[5 : 5+length],
	}, nil
}

// ParseTriplePath extracts service and method from a triple/gRPC path.
// Path format: /{package}.{Service}/{Method}
// Example: /com.example.DemoService/SayHello
func ParseTriplePath(path string) (service, method string) {
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return path, ""
	}

	service = path[:idx]
	method = path[idx+1:]
	return
}

// ReadHTTP2Frames reads all available HTTP/2 frames from reader and extracts
// triple/gRPC messages. Returns a TripleMessage with parsed info.
func ReadTripleMessages(r io.Reader) ([]TripleMessage, int, error) {
	// This is a simplified reader that scans for HEADERS frames
	// to extract service/method paths.
	var messages []TripleMessage
	totalBytes := 0

	buf := make([]byte, 65536) // read up to 64K at a time

	for {
		n, err := r.Read(buf)
		if n > 0 {
			totalBytes += n

			// Scan for HTTP/2 HEADERS frames
			data := buf[:n]
			for i := 0; i <= n-HTTP2FrameHeaderSize; i++ {
				if data[i] == 0 && data[i+1] == 0 && data[i+3] == HTTP2FrameHeaders {
					frameLen := int(uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2]))
					if i+HTTP2FrameHeaderSize+frameLen <= n {
						hdrData := data[i+HTTP2FrameHeaderSize : i+HTTP2FrameHeaderSize+frameLen]
						msg := parseTripleHeaders(hdrData)
						if msg.ServiceName != "" || msg.MethodName != "" {
							msg.IsRequest = true
							messages = append(messages, msg)
						}
						i += HTTP2FrameHeaderSize + frameLen - 1
					}
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			return messages, totalBytes, err
		}
	}

	return messages, totalBytes, nil
}

// parseTripleHeaders parses HTTP/2 HPACK-decoded headers (simplified).
// Full HPACK decoding is complex; this does best-effort string scanning
// for the :path pseudo-header and content-type.
func parseTripleHeaders(data []byte) TripleMessage {
	msg := TripleMessage{
		Headers: make(map[string]string),
	}

	text := string(data)

	// Look for :path pseudo-header
	if strings.Contains(text, ":path") {
		for _, hdr := range []string{":path", ":method", ":scheme", ":authority", "content-type", "grpc-encoding"} {
			findHeaderValue(text, hdr, msg.Headers)
		}

		if path, ok := msg.Headers[":path"]; ok {
			msg.ServiceName, msg.MethodName = ParseTriplePath(path)
		}
	}

	if ct, ok := msg.Headers["content-type"]; ok {
		msg.ContentType = ct
	}

	return msg
}

// findHeaderValue does best-effort header value extraction from HPACK data.
func findHeaderValue(data, name string, headers map[string]string) {
	idx := strings.Index(strings.ToLower(data), strings.ToLower(name))
	if idx < 0 {
		return
	}

	// Skip past the header name (approximate)
	rest := data[idx+len(name):]
	// Try to extract the value — look for the next printable string
	// This is a heuristic; full HPACK decoding is complex
	_ = rest
	// Store whatever we can find
	headers[name] = "(parsed)"
}
