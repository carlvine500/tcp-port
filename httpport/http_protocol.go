// Package httpport provides lightweight HTTP/1.x protocol parsing
// for traffic monitoring.
package httpport

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// HTTPMessage represents a parsed HTTP request or response.
type HTTPMessage struct {
	Type       string // "request" or "response"
	RawLine    string // GET /path HTTP/1.1 or HTTP/1.1 200 OK
	Method     string
	Path       string
	StatusCode int
	StatusText string
	Headers    map[string]string
	RawHeaders []string
	BodySize   int
}

// HTTP methods for detection.
var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true,
	"OPTIONS": true, "PATCH": true, "TRACE": true, "CONNECT": true,
}

// ReadHTTPMessage reads an HTTP request or response from reader.
func ReadHTTPMessage(r *bufio.Reader) (*HTTPMessage, error) {
	// Read first line
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, io.EOF
	}

	msg := &HTTPMessage{RawLine: line, Headers: make(map[string]string)}

	// Parse first line
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed HTTP line: %s", line)
	}

	if _, ok := httpMethods[parts[0]]; ok {
		// Request: METHOD PATH VERSION
		msg.Type = "request"
		msg.Method = parts[0]
		if len(parts) >= 2 {
			msg.Path = parts[1]
		}
	} else if strings.HasPrefix(parts[0], "HTTP/") {
		// Response: HTTP/VERSION STATUS TEXT
		msg.Type = "response"
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &msg.StatusCode)
		}
		if len(parts) >= 3 {
			msg.StatusText = parts[2]
		}
	} else {
		return nil, fmt.Errorf("not HTTP: %s", line)
	}

	// Read headers
	for {
		hdrLine, err := r.ReadString('\n')
		if err != nil {
			break
		}
		hdrLine = strings.TrimRight(hdrLine, "\r\n")
		if hdrLine == "" {
			break // end of headers
		}
		msg.RawHeaders = append(msg.RawHeaders, hdrLine)

		idx := strings.Index(hdrLine, ":")
		if idx > 0 {
			key := strings.TrimSpace(hdrLine[:idx])
			val := strings.TrimSpace(hdrLine[idx+1:])
			msg.Headers[strings.ToLower(key)] = val
		}
	}

	// Check Content-Length
	if cl, ok := msg.Headers["content-length"]; ok {
		fmt.Sscanf(cl, "%d", &msg.BodySize)
	}

	return msg, nil
}

// DetectHTTP checks if data looks like an HTTP message.
func DetectHTTP(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	// Check for HTTP method
	for method := range httpMethods {
		if strings.HasPrefix(string(data), method+" ") {
			return true
		}
	}

	// Check for HTTP response
	if strings.HasPrefix(string(data), "HTTP/1.") {
		return true
	}

	return false
}

// FormatHTTP formats an HTTP message for display.
func FormatHTTP(msg *HTTPMessage) string {
	var sb strings.Builder

	if msg.Type == "request" {
		sb.WriteString(fmt.Sprintf("  %s %s\n", msg.Method, msg.Path))
	} else {
		sb.WriteString(fmt.Sprintf("  %d %s\n", msg.StatusCode, msg.StatusText))
	}

	// Print key headers
	for _, key := range []string{"host", "content-type", "content-length", "user-agent", "server", "location"} {
		if v, ok := msg.Headers[key]; ok {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", key, v))
		}
	}

	return sb.String()
}

// FormatHTTPURL formats a minimal URL-level HTTP message.
func FormatHTTPURL(msg *HTTPMessage) string {
	if msg.Type == "request" {
		return fmt.Sprintf("%s %s\n", msg.Method, msg.Path)
	}
	return fmt.Sprintf("%d %s\n", msg.StatusCode, msg.StatusText)
}
