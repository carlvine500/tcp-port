package nacosport

import (
	"bufio"
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
	Params     map[string]string // query parameters
	Body       string            // request body
	StatusCode int               // HTTP status code (responses only)
	Summary    string            // human-readable summary
	Direction  string            // "C->S" or "S->C"
}

// HTTP methods for detection.
var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true,
	"OPTIONS": true, "PATCH": true, "TRACE": true, "CONNECT": true,
}

// classifyNacosPath determines the API type from a Nacos path.
// Order matters — check more specific patterns first.
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
	return "nacos"
}

// DetectNacos checks if data looks like a Nacos HTTP API message.
// A Nacos message is an HTTP request whose path contains "/nacos/v1/".
func DetectNacos(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	s := string(data)

	// Must start with an HTTP method
	for method := range httpMethods {
		prefix := method + " "
		if strings.HasPrefix(s, prefix) {
			rest := s[len(prefix):]
			// Extract the path (up to space or newline)
			pathEnd := strings.IndexAny(rest, " \r\n")
			path := rest
			if pathEnd > 0 {
				path = rest[:pathEnd]
			}
			if strings.Contains(path, "/nacos/v1/") {
				return true
			}
			return false
		}
	}

	return false
}

// ReadNacosMessage reads a Nacos HTTP request or response from a reader.
// It parses the HTTP framing and extracts Nacos-specific fields.
func ReadNacosMessage(r io.Reader, direction string) (*NacosMessage, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
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
			// Split path and query string
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
		}
	}

	// Read body if present
	if contentLength > 0 {
		body := make([]byte, contentLength)
		_, err := io.ReadFull(br, body)
		if err == nil {
			msg.Body = string(body)
		}
	}

	// Build summary
	msg.Summary = buildSummary(msg)

	return msg, nil
}

// parseQueryParams parses URL query parameters into a map.
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
	if msg.Method != "" {
		// Request summary
		return fmt.Sprintf("[Nacos %s] %s %s", msg.APIType, msg.Method, msg.Path)
	}
	// Response summary
	return fmt.Sprintf("[Nacos] HTTP %d", msg.StatusCode)
}
