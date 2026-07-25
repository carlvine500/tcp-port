package nacosport

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

// NacosMessage represents a parsed Nacos HTTP API request or response.
type NacosMessage struct {
	Method     string            // HTTP method: GET, POST, PUT, DELETE
	Path       string            // URL path: /nacos/v1/ns/instance
	APIType    string            // heartbeat, service, discovery, config, service_list, auth
	Params     map[string]string // query parameters + form body params
	Body       string            // raw request/response body (for display)
	StatusCode int               // HTTP status code (responses only)
	IsJSON     bool              // true if body is JSON
	Summary    string            // human-readable summary
	Direction  string            // "C->S" or "S->C"
}

// HTTP methods for detection.
var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true,
	"OPTIONS": true, "PATCH": true, "TRACE": true, "CONNECT": true,
}

// classifyNacosPath determines the API type from a Nacos path.
func classifyNacosPath(p string) string {
	if strings.Contains(p, "/instance/beat") {
		return "heartbeat"
	}
	if strings.Contains(p, "/instance/list") {
		return "discovery"
	}
	if strings.Contains(p, "/instance") {
		return "service"
	}
	if strings.Contains(p, "/cs/configs") {
		return "config"
	}
	if strings.Contains(p, "/service/list") {
		return "service_list"
	}
	if strings.Contains(p, "/auth/login") {
		return "auth"
	}
	// Nacos 2.x gRPC gateways
	if strings.Contains(p, "/nacos/v2/") {
		return "nacos2"
	}
	return "nacos"
}

// DetectNacos checks if data looks like a Nacos HTTP API message.
// Also detects Nacos 2.x gRPC over HTTP/2.
func DetectNacos(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	s := string(data)

	// HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	// Nacos gRPC uses HTTP/2 — detect via PRI preface
	if strings.HasPrefix(s, "PRI * HTTP/2.0") {
		// Could be Nacos gRPC — accept it for now
		// We'll classify later in the handler
		return true
	}

	// Must start with an HTTP method
	for method := range httpMethods {
		prefix := method + " "
		if strings.HasPrefix(s, prefix) {
			rest := s[len(prefix):]
			pathEnd := strings.IndexAny(rest, " \r\n")
			path := rest
			if pathEnd > 0 {
				path = rest[:pathEnd]
			}
			if strings.Contains(path, "/nacos/") {
				return true
			}
			return false
		}
	}

	return false
}

// ReadNacosMessage reads a Nacos HTTP request or response from a reader.
func ReadNacosMessage(r io.Reader, direction string) (*NacosMessage, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}

	// Peek first bytes to detect HTTP/2 (gRPC) vs HTTP/1.1
	peek, _ := br.Peek(24)
	if len(peek) >= 14 && strings.HasPrefix(string(peek), "PRI * HTTP/2.0") {
		return readNacosGRPC(br, direction)
	}

	// Read request/status line
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, io.EOF
	}

	msg := &NacosMessage{
		Direction: direction,
		Params:    make(map[string]string),
	}

	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed HTTP line: %s", line)
	}

	if _, isReq := httpMethods[parts[0]]; isReq {
		// HTTP request
		msg.Method = parts[0]
		rawPath := ""
		if len(parts) >= 2 {
			rawPath = parts[1]
			if idx := strings.Index(rawPath, "?"); idx >= 0 {
				msg.Path = rawPath[:idx]
				parseQueryParams(msg.Params, rawPath[idx+1:])
			} else {
				msg.Path = rawPath
			}
		}
		msg.APIType = classifyNacosPath(msg.Path)
	} else if strings.HasPrefix(parts[0], "HTTP/") {
		// HTTP response
		msg.Direction = direction
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &msg.StatusCode)
		}
	} else {
		return nil, fmt.Errorf("not HTTP: %s", line)
	}

	// Read headers
	var contentLength int
	var contentType string
	for {
		hdrLine, err := br.ReadString('\n')
		if err != nil {
			break
		}
		hdrLine = strings.TrimRight(hdrLine, "\r\n")
		if hdrLine == "" {
			break
		}

		idx := strings.Index(hdrLine, ":")
		if idx > 0 {
			key := strings.ToLower(strings.TrimSpace(hdrLine[:idx]))
			val := strings.TrimSpace(hdrLine[idx+1:])
			if key == "content-length" {
				contentLength, _ = strconv.Atoi(val)
			}
			if key == "content-type" {
				contentType = strings.ToLower(val)
			}
		}
	}

	// Read body if present
	if contentLength > 0 {
		body := make([]byte, contentLength)
		_, err := io.ReadFull(br, body)
		if err == nil {
			msg.Body = string(body)
			// Parse body into params for form-urlencoded
			if strings.Contains(contentType, "application/x-www-form-urlencoded") {
				parseQueryParams(msg.Params, msg.Body)
			}
			// Detect JSON
			if strings.Contains(contentType, "application/json") {
				msg.IsJSON = true
			}
		}
	}

	// Build summary
	msg.Summary = buildSummary(msg)

	return msg, nil
}

// readNacosGRPC handles Nacos 2.x gRPC over HTTP/2.
func readNacosGRPC(br *bufio.Reader, direction string) (*NacosMessage, error) {
	// Read the HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	preface := make([]byte, 24)
	_, err := io.ReadFull(br, preface)
	if err != nil {
		return nil, err
	}

	msg := &NacosMessage{
		Method:    "GRPC",
		Path:      "/nacos/v2/grpc",
		APIType:   "nacos2",
		Params:    make(map[string]string),
		Direction: direction,
	}
	msg.Summary = "[Nacos 2.x gRPC] connection established"
	return msg, nil
}

// parseQueryParams parses URL-encoded or form-encoded key=value pairs.
func parseQueryParams(params map[string]string, query string) {
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			params[kv[0]], _ = url.QueryUnescape(kv[1])
		} else {
			params[kv[0]] = ""
		}
	}
}

// buildSummary builds a human-readable summary for the Nacos message.
func buildSummary(msg *NacosMessage) string {
	if msg.Method == "GRPC" {
		return "[Nacos 2.x gRPC]"
	}
	if msg.Method != "" {
		return fmt.Sprintf("[Nacos %s] %s %s", msg.APIType, msg.Method, msg.Path)
	}
	if msg.StatusCode > 0 {
		statusText := "ok"
		if msg.StatusCode >= 400 {
			statusText = "error"
		}
		return fmt.Sprintf("[Nacos] HTTP %d (%s)", msg.StatusCode, statusText)
	}
	return "[Nacos]"
}

// ParseJSONBody tries to parse the JSON body into a map.
func ParseJSONBody(body string) (map[string]interface{}, error) {
	var m map[string]interface{}
	err := json.Unmarshal([]byte(body), &m)
	return m, err
}
